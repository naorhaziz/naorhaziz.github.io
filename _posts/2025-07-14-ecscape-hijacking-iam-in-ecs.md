---
title: "ECScape: Hijacking IAM Privileges in Amazon ECS"
layout: post
date: 2025-07-14 14:02:00 +0300
categories: [aws, ecs, security, cloud]
tags: [ecs, iam, container, privilege escalation, blackhat, fwdcloudsec]
image: /assets/img/ecscape/ecscape.png
---

Cloud environments offer unparalleled flexibility and scalability, but they also introduce complex security considerations. In Amazon Web Services (AWS), subtle interactions between services can lead to unexpected vulnerabilities.  In this post, I’ll share how I discovered a critical **cross-container IAM credential theft** vulnerability in Amazon ECS (Elastic Container Service) - a flaw that breaks the assumed role boundaries between ECS tasks. This is the story of **“ECScape,”** an exploit that hijacks IAM privileges across co-located containers, how we pulled it off, and what it means for cloud container security.

**Resources**
- **Conference talks:**  
  - [**Black Hat USA 2025 briefing**](https://www.blackhat.com/us-25/briefings/schedule/#ecs-cape--hijacking-iam-privileges-in-amazon-ecs-45686)  
  - [**fwd:cloudsec 2025 YouTube video**](https://www.youtube.com/watch?v=WXdB-9pTqAU)
- [**POC Source Code**](https://github.com/naorhaziz/ecscape)

**TL;DR**
---------

*   **Vulnerability Discovered:** I found a way to abuse an _undocumented ECS internal protocol_ to grab AWS credentials belonging to other ECS tasks on the same EC2 instance. A malicious container with a low-privileged IAM role can hijack the permissions of a higher-privileged container running on the same host.
    
*   **Real-World Impact:** In practice, this means a compromised app in your ECS cluster could **escalate to admin privileges** by stealing credentials from a more privileged task. This undermines IAM role isolation - _one container can effectively become any other_ in terms of AWS access.
    
*   **How It Works:** Amazon ECS tasks retrieve credentials via a local metadata service (169.254.170.2) and a unique credentials **endpoint** for each task. We discovered that by exploiting how ECS identifies tasks in this process, an attacker can **masquerade as another task** and obtain its temp credentials. No container breakout (root on host) was required - just clever network and system trickery within the container’s namespace.
    
*   **Stealth Factor:** The stolen keys work exactly like the real task’s keys - **CloudTrail / CloudWatch logs show the victim task** making the API calls, so initial detection is tough.
    
*   **Mitigations:** If you run ECS on EC2, avoid deploying high-privilege tasks alongside untrusted or low-privilege tasks on the same instance. Consider **dedicated hosts** or node isolation for critical services, or use AWS Fargate (each task in its own VM) for true separation. **Disable IMDS access for tasks** wherever possible (block 169.254.169.254, enable IMDSv2, or use the ECS AWSVPC\_BLOCK\_IMDS setting). Also enforce least privilege on all tasks and drop unneeded Linux capabilities (to limit what a compromised container can do). We’ll cover best practices and detection hints later in this post
    

**Recommended Primers**

If any of the acronyms below feel rusty, a quick skim of these docs will make the deep-dive smoother:

*   [AWS Identity & Access Management (IAM)](https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html) 
    
*   [Amazon EC2 basics](https://docs.aws.amazon.com/ec2/index.html)
    
*   Docker fundamentals
    
*   [IMDS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
    
*   [Amazon ECS overview](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/Welcome.html) 
    
*   [Signature Version 4 (SigV4)](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
    
*   [AWS control-plane vs. data-plane](https://aws.amazon.com/blogs/security/](https://docs.aws.amazon.com/whitepapers/latest/aws-fault-isolation-boundaries/control-planes-and-data-planes.html))
    
*   [AWS Fargate](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/AWS_Fargate.html)
    

**Before We Begin: Why the Host Really Matters**
----------------------------------------------------------

Everything you’re about to see happens **inside a single EC2 instance** that’s running the ECS agent and multiple containers. Understanding the host’s moving parts is crucial, because ECScape exploits the boundary where **ECS convenience meets shared-host reality**.

**The EC2 Host and the ECS Agent: Under the Hood**

Even though ECS abstracts away a lot of complexity, when using the EC2 launch type there is still an EC2 server underneath every task. Let’s break down what’s happening on that container host, because ECScape abuses the host-level infrastructure:

### **EC2 Instance Metadata Service (IMDS)**

*   Every EC2 instance has a special link-local HTTP endpoint 169.254.169.254 that provides metadata about the instance. 
    
*   Crucially, **IMDS can provide temporary AWS credentials for the instance’s IAM role**. In practice, any process on the instance can query http://169.254.169.254/latest/meta-data/iam/security-credentials/{role\_name} to retrieve the current set of credentials (Access Key, Secret Key, Session Token) for the instance role.
    
*   **By default, IMDS is enabled on ECS cluster instances**, and by default nothing prevents containers from accessing it. This is a key initial weakness: **any ECS task by default can read the instance’s role credentials via IMDS** if not explicitly blocked. Those instance role credentials will later be used to impersonate the ECS agent.
    

### **ECS Agent**

*   Privileged process (actually a Docker container itself running with --privileged rights on the host) that manages ECS tasks. 
    
*   Provided by AWS (open-source on GitHub) and runs automatically on ECS-optimized AMIs or when you install it on your EC2. 
    
*   The agent’s responsibilities include:
    
    *   **Registering the instance** to the ECS control plane (so it appears in your cluster) and maintaining a heartbeat.
        
    *   **Pulling container images** from ECR (or other registries) and launching/stopping containers via Docker.
        
    *   **Setting up networking** for tasks (creating veth interfaces, configuring iptables rules to enforce isolation and to allow the task to reach AWS endpoints like IMDS or ECR as needed).
        
    *   **Fetching task credentials:** When a new task with an IAM role starts, the agent calls STS to assume that task role (using the instance role’s permissions to do so), and then provides the credentials securely to the container.
        

### **ecsInstanceRole**

*   The default IAM role for every EC2 host in an ECS cluster
    
*   The role lets the ECS agent do its day-to-day chores:
    
    *   **Cluster-level control-plane calls:** ecs:RegisterContainerInstance, ecs:DiscoverPollEndpoint, ecs:Poll, ecs:StartTelemetrySession
        
    *   **Image pulls:** ecr:GetAuthorizationToken, ecr:BatchGetImage
        
    *   **Logging & metrics:** logs:CreateLogStream, logs:PutLogEvents
        
    *   **Role impersonation:** sts:AssumeRole on any task role so the agent can hand out the right temp credentials to each task.
        
*   **How the agent gets its own keys**: It transparently **queries IMDS** (169.254.169.254/latest/meta-data/iam/security-credentials/ecsInstanceRole) to retrieve and refresh these credentials - exactly the same curl an attacker can run from inside any container if IMDS isn’t blocked.
    

### **From Host Role to Task Role - Where Isolation Should Happen**

So far we’ve looked at the **ecsInstanceRole** (the host-level identity) and how the ECS agent wields it. But isolation in ECS hinges on the next hop: **each running task is supposed to receive its own short-lived IAM role** - and only that role. The agent’s job is to fetch those credentials and hand them to the right container without anyone else seeing them. The following workflow shows how that vending process is supposed to guarantee task-level separation - and sets the stage for how ECScape breaks it.

AWS documentation:

### **Credential Vending to Tasks: Convenience vs. Risk**

How do containers actually get their unique AWS credentials? Here’s the lifecycle, which is important to understand both the intended isolation and where it can break:

1.  **Agent assumes the task role:** When a task starts, the ECS agent on the host invokes sts:AssumeRole using the instance role credentials. The target is the IAM role specified in the task definition. If successful, STS returns a **credential set** (AccessKeyId, SecretAccessKey, SessionToken, expiration) for that role. This credential is tagged with the role and the task (so CloudTrail can later show which task assumed it).
    
2.  **Agent stores the credentials and exposes them via metadata endpoint:** The ECS agent runs a local HTTP server on the host (at another link-local address 169.254.170.2). It will store the new task credentials and serve them at a unique path, e.g. http://169.254.170.2/v2/credentials/ - where is a UUID specific to that task’s credentials.
    
3.  **Agent updates iptables:** To enforce isolation, the agent programs the host’s firewall (iptables) to allow the specific task’s network namespace to access **only** its own credentials URL on 169.254.170.2. In other words, it DNATs or maps that particular URL so that if Container A tries to hit 169.254.170.2/v2/credentials/A-UUID, it will succeed, but if it tries to hit B-UUID (credentials for another task), it should be blocked.
    
4.  **Container receives the URI:** The agent injects an environment variable into the container’s environment: AWS\_CONTAINER\_CREDENTIALS\_RELATIVE\_URI=/v2/credentials/. This tells the AWS SDK inside the container where to fetch credentials. When the container makes AWS SDK calls, the SDK will issue a HTTP GET to the credential endpoint (which resolves to the agent’s IP) and retrieve the JSON blob of credentials.
    
5.  **Credential rotation:** These role credentials are short-lived (usually up to 6 hours by default for ECS task roles). The agent will proactively refresh them by calling STS again before expiration and update the values served at the same URI, so the container can continuously operate with valid creds.
    

This mechanism means developers don’t have to bake AWS keys into their containers or fetch them from elsewhere - it’s automatically managed by ECS. The **downside** is that a lot of trust is placed on the network namespace and firewall rules isolating that credential service. If a container can break out of its network restrictions or otherwise query the agent’s credential service for another task’s ID, it would immediately obtain those other credentials. **In short, the security of task role isolation hinges on the correctness of the ECS agent and its namespace isolation.** ECScape will exploit the ECS agent in a different way, but it’s worth noting this general principle: containers are not hard security boundaries. A misconfiguration or vulnerability in the isolation can be catastrophic (any weakness in those iptables rules can let one container reach data meant for another, it instantly inherits the neighbor’s AWS permissions).

With this background, we can now understand how ECScape was discovered and how it works step-by-step.

**Discovery**
-------------

I didn’t set out to break ECS; my original goal was to finish an **eBPF-based monitoring tool** that could watch ECS workloads in real time. To build accurate per-task dashboards, I needed a quick, local way to map **processes → containers → ECS tasks** and then tag them with **cluster, task ARN, and service name**.

While experimenting, I first tried to scrape the **Docker container labels** that ECS automatically adds to each task. Those labels neatly include the **task ARN, task definition family, revision, cluster ARN, and container name** - but **the service name is conspicuously absent**. 

![Alt text](/assets/img/ecscape/docker_labels.jpg)

For a monitoring dashboard, that one field matters; without it, I can’t group traffic by service or alert on service-level anomalies.That led me to the **ECS Task Metadata Endpoint v4** - an HTTP service the **ECS agent** exposes at 169.254.170.2/v4/… inside every task’s network namespace. Querying it from inside a container returned exactly the fields I needed: **service name**, task-definition family, revision, and more. 

![Alt text](/assets/img/ecscape/service_name.jpg)

Naturally, I wondered if my eBPF sensor could simply **mimic the agent**: query the same endpoint and stitch the data together. But when I inspected the **ecsInstanceRole** attached to the host, I noticed something odd: it **does not have ecs:ListServices or any API that would normally reveal a service name**. Yet the agent obviously knew that name- enough to hand it to me over the metadata endpoint.

Curiosity led me down a rabbit hole of packet capture. I set up a small local proxy to watch the traffic between the ECS agent and the AWS endpoints. **What I observed was startling:**

*   The ECS agent established a WebSocket connection to an AWS endpoint (what I later learned is the **Agent Communication Service (ACS)**).
    
*   In the handshake request, a query parameter stood out: ?sendCredentials=true.
    
*   Shortly after, across this WebSocket, I saw cleartext JSON blobs that looked very much like **IAM credentials for tasks**. They contained access key IDs, secret keys, session tokens – the credentials that the agent would later serve to the respective containers.
    
![Alt text](/assets/img/ecscape/task_credentials.jpg)

At this moment, I realized that **the ECS control plane was actively sending task credentials down to the agent** over this WebSocket channel. Normally, this is fine - it’s how the agent gets the credentials to give to containers - but if I could tap into that channel, I might capture credentials not meant for me. My thought was: If the control plane hands out all task credentials to the agent, could I pose as the agent and trick AWS into sending me those credentials?

That question was the genesis of **ECScape** - an attack that is essentially about escaping the container’s confines and impersonating the ECS agent to access everything.

**The ECScape Exploit: Impersonating the ECS Agent to Steal All Credentials**
-----------------------------------------------------------------------------

Now we’ll walk through how ECScape actually works in practice, step by step. The goal for the attacker (a malicious process in one container) is to obtain the IAM credentials of all other tasks on the same EC2 host. To do this, the attacker will:

1.  **Obtain the host’s IAM role credentials** (so it can act as the ECS agent).
    
2.  **Discover the ECS control plane endpoint** that the agent talks to.
    
3.  **Gather necessary identifiers** (cluster, container instance ID, etc.) to authenticate as the agent.
    
4.  **Establish a fake agent session** (WebSocket) with the ECS control plane and request sendCredentials.
    
5.  **Receive credentials** for all running tasks on that instance, then use them for further exploitation.
    

Let’s break these down:

### **Step 1: Steal EC2 Instance Role Credentials via IMDS**

The attacker starts from **within a compromised container** (any low-privileged ECS task running on EC2). Because IMDS is available by default, the container can query the instance metadata service. A simple curl request to http://169.254.169.254/latest/meta-data/iam/security-credentials/{InstanceProfileName} will yield the **Access Key, Secret Key, and Session Token** for the EC2 host’s role. These are the credentials the ECS agent normally uses. Now the malicious container has them.

At this point, the attacker essentially holds the identity of the ECS agent (or more accurately, the identity of the entire EC2 instance in AWS’s eyes). These credentials typically have names like ecsInstanceRole/instance-id in CloudTrail logs, indicating an STS session for the instance role. With these, the attacker can do a lot of things the agent can do – but importantly, they cannot directly assume a task role yet, because while they have the power to call sts:AssumeRole, they would need to know each task role’s ARN and do it one by one. There’s an easier route: let AWS give them all the credentials via the agent’s channel.

**Security Note:** There will be **CloudTrail logs** for this initial step only if the attacker uses the stolen credentials outside the instance. Simply reading IMDS does not create a CloudTrail event (it’s just an HTTP GET on the instance). But any subsequent AWS API calls made with these credentials (like in the next steps) will show up in CloudTrail as actions performed by the instance role. For example, calling ecs:DiscoverPollEndpoint or ecs:Poll (next steps) will be logged as the instance role calling those APIs.

### **Step 2: Discover the Poll Endpoint URL (ecs:DiscoverPollEndpoint)**

The ECS agent doesn’t communicate with the control plane at a generic public endpoint; AWS provides a specific **polling endpoint** for each cluster/instance. Using the stolen instance role creds, the attacker calls the ecs:DiscoverPollEndpoint API. This call returns a URL like https://ecs-a-1..amazonaws.com. This is essentially telling the agent, “here is the endpoint to connect to for receiving ACS messages for your cluster.”

If for some reason this API call fails, it’s worth noting the endpoint is somewhat predictable (it usually includes the region and some enumeration). In some research I did, it turned out one could brute-force or guess the URL if needed, but in most cases, using the API is straightforward and allowed by the instance role’s policy.

Now the attacker knows where to initiate the connection for the control plane communications.

### **Step 3: Gather Required Identifiers (Cluster, Container Instance, etc.)**

When the ECS agent connects to ACS, it includes various identifiers so the backend knows which cluster and which specific container instance (EC2 host) is checking in. The attacker needs to supply these to mimic the agent. Important values include:

*   **Cluster ARN:** identifies the ECS cluster name and AWS account/region.
    
*   **Container Instance ARN:** the unique ARN assigned to the EC2 instance within the cluster.
    
*   **Agent version info:** a client version string, which the backend might expect (this could be as simple as including the agent version in headers or query).
    
*   **Docker Version:** Docker daemon version.
    
*   **Protocol Version**
    
*   **Sequence Number**
    

How to get these? The ECS Task Metadata endpoint (169.254.170.2/v4/...) accessible from the container can provide the **Cluster ARN** easily, as well as details about the task. The tricky one was the **Container Instance ARN** (the identity of the host in the ECS cluster). This isn’t directly given in the task metadata by default.

However, ECS has another introspection endpoint on the agent (normally used on the host, not from inside a container) that can list the container instance ARN. In practice, I discovered that by querying a certain path or using the agent’s local credentials, you could retrieve the container instance ARN. In some cases, one could also call ecs:ListContainerInstances with the cluster, but that might require additional IAM permissions that the instance role may not grant freely. In my exploit, I leveraged an **introspection API** that the agent exposes - this returned all the info I needed, including the container instance ARN and even the agent’s software version.

The fact that a container could access the agent’s introspection API is itself a minor isolation gap. Normally, that API might be bound to localhost or a unix socket, but if it’s on the link-local and the iptables aren’t filtering it out, a container could reach it. This is a smaller part of the exploit chain, but highlights how a single oversight can aid an attacker.

Armed with the identifiers, the attacker is ready to masquerade as the agent.

### **Step 4: Craft and Sign the WebSocket Connection (ecs:Poll via ACS)**

Using the data above, the attacker constructs a WebSocket handshake to the previously obtained Poll endpoint URL (from Step 2). This request must be **SigV4-signed** using the instance role credentials - essentially treating the WebSocket upgrade as a signed HTTPS request. 

I added the query parameter sendCredentials=true to the URL - this is the magic flag that tells the ACS (Agent Communication Service) that, upon connecting, the agent is interested in receiving IAM credential payloads for all tasks. 

With the signing complete (including proper AWS date headers, authorization header, etc.), I initiated the WebSocket connection. Thanks to the correct SigV4 auth and the correct identifiers in place, the backend accepted my connection as if I were the legitimate ECS agent on that container instance. From AWS’s perspective, my process was now just another **(authorized) agent** connecting from that instance.

It’s important to note: the ECS backend did not immediately invalidate the real agent’s session. In fact, I ended up with two concurrent connections for the same container instance - one was the real agent, and one was my impersonating session. The control plane effectively **broadcasted** messages to both connections. (Had AWS limited it to one connection at a time, my exploit might have knocked the real agent offline, which could raise flags. But here, I could stay stealthy, just eavesdropping.)

### **Step 5: Receive All Task Credentials from ACS**

Once the WebSocket handshake succeeded, I was effectively “inside” the **Agent Communication Service (ACS)** stream. ACS is a proprietary, JSON-encoded protocol that rides over a long-lived WebSocket between every ECS agent and the regional control-plane shard that manages its cluster. The channel is multiplexed:

*   **Heartbeat + Ack** - Keep-alive pings, sequence confirmation.
    
*   **Task Manifest** - ”Start / stop these containers” directives.
    
*   **IAM Role Credentials**
    
*   **…**
    

Essentially, the ECS control plane sent down an IamRoleCredentials message for each running task on that instance. This included:

*   The **Task ARN** and role identifier,
    
*   The Access Key ID, Secret Access Key, Session Token, and expiration for that task’s role session,
    
*   An internal credential ID (the UUID used in the metadata path).
    

I saw multiple such messages, corresponding to every task that was currently running on the host. For example, if there were 5 tasks (containers) on the instance (including my own malicious one), I received 5 sets of credentials - one of which corresponded to my own task (which I already had access to anyway), and the others corresponded to roles that were not assigned to me.

At this point, the isolation was completely broken: I, in a low-privileged container, had just acquired the IAM privileges of **all other tasks** sharing the EC2 instance. In a realistic scenario, those other tasks might include things like:

*   A backup task with broad read/write access to S3 or databases,
    
*   A CI/CD task with permissions to deploy infrastructure (CloudFormation, etc.),
    
*   Monitoring or logging tasks with access to sensitive data or the ability to assume other roles.
    

I could now take those credentials and do whatever those roles allowed. For instance, in my demo, one of the target tasks had an admin-like role. Using its keys, I was able to perform high-privilege AWS actions (like deleting an S3 bucket) which my original container’s role was never permitted to do.

Crucially, because I carefully mimicked the protocol (including sending back expected acknowledgments for each message to ACS), the ECS service didn’t flag anything as wrong. To the ECS control plane, it was business as usual, as if the agent simply got the credentials and acknowledged them. The real ECS agent on the host also received these messages, but it was none the wiser that someone else was listening in.

Throughout this process, **CloudTrail logs** would show the following:

*   The DiscoverPollEndpoint and the WebSocket connection (authenticated via ecs:Poll) would appear as API calls made by the **container instance role**. This is somewhat normal traffic for an ECS host (though typically these calls come from the agent at startup or periodically, not randomly from a container’s actions).
    
*   The actual use of stolen credentials: If I immediately use the stolen task creds to call AWS APIs, CloudTrail will log those API calls under the assumed role (the task role’s ARN). From AWS’s point of view, it looks like that task’s role just did something. However, interestingly, because the role session is tied to the original task, CloudTrail might show the **task ARN** in the session context. If I, as Task B, use Task A’s credentials to call, say, s3:DeleteBucket, the CloudTrail entry will list Task A’s role and possibly Task A’s ARN as the session name. This is a potential detection vector: Task A’s role is doing something it normally doesn’t, or doing it at an odd time.
    

In summary, ECScape allowed a complete breach of the ECS task isolation on an EC2 host: a compromise of one container led to impersonation of the host’s agent and theft of all other containers’ IAM privileges. This is a cloud privilege escalation of significant magnitude.

![Alt text](/assets/img/ecscape/ecscape_diagram.jpg)

**Impact: Why ECScape Is So Severe**
------------------------------------

The implications of ECScape are far-reaching:

*   **Cross-Task Privilege Escalation:** A fundamental promise of containerized workloads is that one compromised app remains isolated from others. ECScape shatters that for ECS on EC2. A low-privileged task can become a high-privileged one by simply stealing its credentials. In effect, any task can become any other task on the same host, permission-wise. This breaks multi-tenancy and defense-in-depth assumptions. For example, if you had a security scanning container (with read-only access to some data) running alongside a database backup container (with full database access), a breach in the scanner container could now also compromise your database by assuming the backup container’s role.
    
*   **Host Role Impersonation:** By stealing the **ecsInstanceRole** credentials from IMDS, an attacker can also impersonate the container **instance** itself at the ECS control plane. This means they could potentially register fake tasks, stop tasks (Denial of Service), or even register new container instances into the cluster. Essentially, they can pretend to be the ECS agent and manipulate the cluster state. In a worst case, they could drain the actual tasks and replace them with malicious ones (since the instance role often has the capability to update the ECS agent heartbeat and respond to ACS directives).
    
*   **Metadata Exfiltration & Reconnaissance:** Impersonating the agent gives more than just keys. The ACS stream also carries rich task-level metadata:
    
    *   full lists of running Task ARNs and Task Definition revisions
        
    *   container image digests, CPU/MEM reservations, network settings
        
    *   ENI IDs, private IPs, and the instance’s own attributes (AMI ID, AZ, etc.)
        
*   **Stealth and Lack of Immediate Detection:** The actions taken in ECScape are not obviously noisy. Everything the attacker does can appear as normal API calls from the perspective of AWS:
    
    *   The calls to ecs:Poll and related APIs are typical for an ECS agent (though timing and frequency might be a clue).
        
    *   Using stolen credentials to access resources will just look like the legitimate role doing so. CloudTrail does record which role (and the task ARN context) performed an action, but it won’t scream “stolen credentials” without additional analysis. If an attacker is careful to use the creds in ways that blend in with normal activity (e.g., reading data the role usually reads, or slowly exfiltrating), it might not raise immediate flags.
        
*   **CloudTrail and Audit Artifact:** There is a silver lining: because each set of task credentials is tied to a task ARN, any use of those credentials will have an audit trail pointing to that task’s identity. So if Task A’s credentials were used to do admin actions, an investigator can see “Task A’s role did X at time Y”. If Task A was not supposed to do that, it indicates something was wrong. This at least provides a clue during incident response. As AWS has noted in documentation, **CloudTrail will show which task is using which role** for API calls. In an ECScape scenario, you'd see one task's role being used at times the task wasn’t actually performing those actions.
    
*   **No Misconfiguration Required:** Perhaps the scariest part: this exploit does **not** rely on any obvious misconfiguration by the user. All default settings (IMDS enabled, instance role with default ECS permissions, tasks on the same instance) are enough for the attack to work. **Hundreds of millions of ECS tasks** running with these default conditions were hypothetically vulnerable. This is not a case of “you should have locked that down”; it’s a case of the default isolation not holding up against a creative attack.
    
*   **Full Cloud Takeover Scenarios:** If any of the tasks on the instance had highly privileged IAM roles (say a task that has administrative rights, or access to credentials of other accounts, etc.), the attacker can jump to that and potentially pivot to own the entire AWS account. Even without an admin task, the attacker could combine permissions from multiple tasks. For example, Task A’s stolen creds let them read some secrets from AWS Secrets Manager; Task B’s creds let them use those secrets to connect to an internal service; Task C’s creds allow sts:AssumeRole into another account… etc. In a complex environment, this can be an effective way to chain into deeper access.
    

In a live demonstration of ECScape, I showed exactly this: I started in a task that had a policy of “deny all” (it wasn’t allowed to call any AWS API). On the same host, another task had a role with broad permissions (for demonstration purposes, say an admin role). Using ECScape, the low-privileged task obtained the admin credentials of the other task and then used those credentials to delete an S3 bucket that only an admin could delete. The takeaway is clear – a breach of one container could directly result in compromise of critical resources.

![Alt text](/assets/img/ecscape/impact.jpg)

**Mitigation and Best Practices for ECS**
-----------------------------------------

AWS’s official response to this issue emphasized that it was working as designed from their perspective (more on that later), and thus they did not issue an immediate patch to change ECS behavior. This means it’s on AWS users to harden their ECS on EC2 environments. Here are important mitigation steps and best practices:

*   **Disable or Limit IMDS Access for Tasks:** The instance metadata endpoint is the source of the instance role credentials. If your containers have no reason to query IMDS, you should prevent them from being able to reach it. AWS now provides ways to **disable IMDSv1** and require IMDSv2, or even disable IMDS for the instance entirely – but **do not disable IMDS for the instance role on ECS EC2 hosts**, or the ECS agent itself will break. Instead, you can use network policies (iptables rules, VPC routing tricks, or ECS task network settings) to block 169.254.169.254 from within the containers’ network namespace. For example, if you use the awsvpc network mode, consider using security groups that block egress to 169.254.169.254 for the container ENI. Alternatively, ECS now supports a feature to **deny IMDS for specific tasks** at the agent level (for bridge network mode tasks). This is the single most effective mitigation: if a container cannot access IMDS, it cannot directly steal the instance credentials needed for ECScape.
    
*   **Restrict ecs:Poll Permissions (if possible):** The instance role needs ecs:Poll for the agent to function, so you can’t remove it from the instance role. However, be cautious not to inadvertently grant ecs:Poll or ecs:DiscoverPollEndpoint to any task roles. In normal setups you wouldn’t, but if someone used wildcards in IAM policies (like ecs:\*), a task might directly have those permissions and could initiate the exploit without needing the instance creds (this would be a misconfiguration).
    
*   **Separate High-Privilege and Low-Privilege Tasks:** If possible, do not co-locate highly sensitive tasks (those with admin or broad IAM roles) on the same EC2 instances as untrusted or less critical tasks. By isolating sensitive workloads to dedicated instances or even using Fargate, you reduce the risk of an ECScape-style cross-contamination. Essentially, treat the EC2 host as a failure domain: everything running on the same host should have a similar level of trust. This might mean running separate ECS clusters or capacity providers for different sensitivity levels.
    
*   **Use AWS Fargate for Stronger Isolation:** Because Fargate tasks do not share an underlying host (each task gets its own microVM with its own instance metadata and agent), ECScape does not apply there. If your security requirements are very strict, it may be worth the cost trade-off to run certain workloads on Fargate. AWS explicitly recommends Fargate for multi-tenant scenarios where you don’t want this kind of cross-task risk.
    
*   **Task IAM Least Privilege:** As always, ensure each task’s IAM role has the minimum permissions needed. This won’t prevent ECScape, but it can limit the damage. If Task A doesn’t actually need admin rights, then even if it’s compromised, Task B stealing its creds wouldn’t gain admin rights. Also, if an attacker compromises one low-privileged task and all other tasks on the instance are also low-privileged, the net gain is small. Segmentation of roles can really pay off here.
    
*   **Monitoring and Detection:** Set up alerts for suspicious activity:
    
    *   CloudTrail insights or Config rules to flag if an IAM role (especially a task role) is suddenly being used in unusual ways or times. For instance, if a backup task’s role is used outside of backup hours, or if it performs an API call it never did before, that could be a red flag.
        
    *   AWS GuardDuty can detect things like an EC2 instance role’s credentials being used from an IP outside AWS (which could indicate IMDS theft and external use). It might also flag abnormal behavior like an instance making API calls that deviate from baseline.
        
    *   On the host, you could monitor network connections. The ECS agent normally connects to specific endpoints. If a container suddenly opens a WebSocket to an AWS domain that it normally wouldn’t, that’s suspicious. Tools could be built to watch for use of the instance role credentials from within containers (though that’s a hard problem without something like a sidecar or specialized agent).
        

By implementing the above, especially the IMDS lockdown per task, you can significantly reduce the risk of an attack like ECScape. In fact, AWS’s updated documentation on ECS task IAM roles now explicitly warns that “tasks running on the same EC2 instance may potentially access credentials belonging to other tasks on that instance” and strongly encourages considering Fargate for stronger isolation

**AWS’s Response and Final Thoughts**
-------------------------------------

When we reported ECScape to AWS, they acknowledged the behavior but stated that it **“does not present a security concern for AWS”** – essentially, they viewed it as operating within the expected trust model of EC2. Containers on the same VM are, in AWS’s eyes, supposed to be mutually distrusting and the customer’s responsibility to isolate if needed. AWS did not issue a CVE or a formal security bulletin, as they often do for vulnerabilities that break their security boundaries.

![Alt text](/assets/img/ecscape/aws_response.jpg)

However, they took two noteworthy actions:

*   **Documentation Update:** AWS updated their public documentation to make it crystal clear that on EC2-backed ECS, one container could grab credentials intended for another if the user isn’t careful. The docs now highlight that task credentials are isolated at the instance level (not absolute isolation) and mention the scenario and the recommendation to use Fargate for stronger guarantees. They also emphasize auditing of task role usage via CloudTrail.
![Alt text](/assets/img/ecscape/aws_doc_change.jpg)

*   **Recognition:** While we didn’t receive a bounty (since it was arguably “working as designed”), AWS did provide a statement of appreciation and said they would add public recognition for the research contribution in their documentation change log. In other words, it was an important enough finding to warrant a doc change and acknowledgment, but not a “vulnerability” in the traditional sense from AWS’s perspective.
    

From my point of view as the researcher, ECScape was a fascinating journey through AWS’s internals. It underscores a lesson in cloud security: **assume breach** at the unit level (here, the container) and consider what blast radius that breach has. AWS provides great primitives like IAM roles for tasks, but the underlying reality is that if those tasks share a host, there is a shared fate to some extent. As AWS moves more toward isolated paradigms (like Fargate’s per-task VM or Kubernetes pods with strong isolation), these risks diminish – but in the here and now, many organizations still run multi-tenant or multi-role tasks together on EC2 clusters.

In conclusion, the ECScape story is a reminder that in cloud security, the lines between configuration, vulnerability, and design choices can be blurry. It also demonstrates the importance of defense in depth: if any one layer (IMDS access, network namespace isolation, IAM least privilege) had broken the chain, the attack would fail. As cloud users, we should strive to add those layers where we can, and as cloud providers, AWS and others will hopefully provide more granular controls or isolated runtimes to mitigate such issues by design in the future.

Thank you for reading this deep dive. If you have similar experiences or thoughts on ECS security, feel free to share! By shining a light on this mechanism, I hope others will secure their ECS deployments or at least monitor them more vigilantly.