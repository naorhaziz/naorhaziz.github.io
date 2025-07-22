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
    
    *   **Instance registration & heartbeat:** Registers the EC2 instance with the ECS control plane and continuously polls (long‑poll) for task and state change directives.

    *   **Task lifecycle management:** Creates, starts, stops, and monitors containers according to the control plane’s desired state directives; relays status updates (RUNNING, STOPPED, exit codes, health, etc.).
        
    *   **Image pulls coordination:** Orchestrates image pulls via the local runtime. For private ECR, it requests an auth token from the ECS control plane; the control plane uses the task execution role (if specified) to authorize ECR/Secrets/Logs actions—those creds are not exposed to your application.

    *   **Networking setup:** Sets up veth pairs / CNI configuration, attaches ENIs (for awsvpc mode), and may program iptables rules (older bridge/host modes) for isolation and routing to AWS endpoints (IMDS, 169.254.170.2, etc.).

    *   **Logs / telemetry relay:** Ships container/task state changes; integrates with CloudWatch Logs/FireLens configurations (the actual CloudWatch API calls again authorized via the execution role at the service side).
        
    *   **Credential delivery:** When a task specifies a task role, the ECS control plane service (ecs-tasks.amazonaws.com) performs the sts:AssumeRole. The resulting short‑lived credentials are pushed down to the agent, which caches and serves them only to the correct task/container via the task metadata / credentials endpoint (169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI).        

### **ecsInstanceRole**

*   A _typical_ default IAM role (instance profile) attached to ECS EC2 hosts (name can be different; ecsInstanceRole is just the common default).
    
*   Has the **managed policy** AmazonEC2ContainerServiceforEC2Role (plus any custom additions you made).
    
*   Grants the ECS agent only the permissions it needs to register with the cluster and operate tasks – **not** your application’s task IAM permissions.
    
**Key allowed actions:**

*   _Control plane:_ ecs:RegisterContainerInstance, ecs:DiscoverPollEndpoint, ecs:Poll, ecs:Submit\*, ecs:StartTelemetrySession
    
*   _ECR auth & image pulls:_ ecr:GetAuthorizationToken, ecr:BatchGetImage
    
*   _Logging/metrics:_ logs:CreateLogStream, logs:PutLogEvents    

![Alt text](/assets/img/ecscape/ecs_instance_role.png)

**How the agent gets credentials**

It transparently **queries IMDS** (169.254.169.254/latest/meta-data/iam/security-credentials/ecsInstanceRole) to retrieve and refresh these credentials - exactly the same curl an attacker can run from inside any container if IMDS isn’t blocked.

**Important distinctions**

*   This role ≠ _task role_. Task/application credentials are assumed by the ECS **control plane** and pushed down separately.
    
*   Keep the instance role minimal; don’t add broad sts:AssumeRole or ecs:\* wildcards unless required.

### **From Host Role to Task Role - Where Isolation Should Happen**

So far we’ve looked at the **ecsInstanceRole** (the host-level identity) and how the ECS agent wields it. But isolation in ECS hinges on the next hop: **each running task is supposed to receive its own short-lived IAM role** - and only that role. The agent’s job is to fetch those credentials and hand them to the right container without anyone else seeing them. The following workflow shows how that vending process is supposed to guarantee task-level separation - and sets the stage for how ECScape breaks it.

AWS documentation:

![Alt text](/assets/img/ecscape/aws_doc_before.jpg)


### **Credential Vending to Tasks: Convenience vs. Risk**

How do ECS tasks get AWS credentials ? The actual lifecycle:

* **Control plane assumes roles:** When ECS schedules a task, the ECS service principal (`ecs-tasks.amazonaws.com`) calls `sts:AssumeRole` for the *execution role* (image pulls / secrets / logs) and the *task role* (your app’s AWS API access).

* **Credentials pushed to agent (ACS):** The control plane sends `IamRoleCredentials` messages over the long‑lived agent (ACS) connection. Each message carries: credentialsId, access key, secret key, session token, expiration.

* **Agent caches & serves:** The agent stores these in memory and exposes the *task role* credentials. It injects  
  `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/<credentialsId>` (or the v3/v4 equivalent) into the container’s environment. Execution role credentials are **not** exposed to the application.

* **Task retrieves on demand:** The SDK inside the container HTTP GETs that relative URI and receives only its own credential JSON. Isolation relies mainly on per‑task network namespaces (awsvpc) + unguessable credential path + the agent returning only a matching `credentialsId`—not on per‑path iptables filtering in modern setups.

This mechanism means developers don’t have to bake AWS keys into their containers or fetch them from elsewhere - it’s automatically managed by ECS. The **downside** is that a lot of trust is placed on the network namespace and firewall rules isolating that credential service. If a container can break out of its network restrictions or otherwise query the agent’s credential service for another task’s ID, it would immediately obtain those other credentials. **In short, the security of task role isolation hinges on the correctness of the ECS agent and its namespace isolation.** ECScape will exploit the ECS agent in a different way, but it’s worth noting this general principle: containers are not hard security boundaries. A misconfiguration or vulnerability in the isolation can be catastrophic (any weakness in those iptables rules can let one container reach data meant for another, it instantly inherits the neighbor’s AWS permissions).

With this background, we can now understand how ECScape was discovered and how it works step-by-step.


**Discovery**
-------------

I didn’t set out to break ECS; my original goal was to finish an **eBPF-based monitoring tool** that could watch ECS workloads in real time. To build accurate per-task dashboards, I needed a quick, local way to map **processes → containers → ECS tasks** and then tag them with **cluster, task ARN, and service name**.

While experimenting, I first tried to scrape the **Docker container labels** that ECS automatically adds to each task. Those labels neatly include the **task ARN, task definition family, revision, cluster ARN, and container name** - but **the service name is conspicuously absent**. 

![Alt text](/assets/img/ecscape/docker_labels.jpg)

For a monitoring dashboard, that one field matters; without it, I can’t group traffic by service or alert on service-level anomalies.That led me to the **ECS Task Metadata Endpoint v4** - an HTTP service the **ECS agent** exposes at 169.254.170.2/v4/… inside every task’s network namespace. Querying it from inside a container returned exactly the fields I needed: **service name**, task-definition family, revision, and more. 

![Alt text](/assets/img/ecscape/service_name.jpg)

Naturally, I wondered if my eBPF sensor could simply **mimic the agent**: query the same endpoint and stitch the data together. But when I inspected the **ecsInstanceRole** attached to the host, I noticed something odd: it **does not have ecs:ListServices or any API that would normally reveal a service name**. Yet the agent obviously knew that name - enough to hand it to me over the metadata endpoint.

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

At this point the attacker possesses **the instance profile’s STS session credentials** (an identity representing the EC2 _container instance_). **These are** _**not**_ **the task role credentials and do** _**not**_ **automatically allow assuming task roles** because:

*   Typical ECS task roles **trust the service principal** ecs-tasks.amazonaws.com, _not_ the instance role.
    
*   The instance profile policy usually lacks sts:AssumeRole permission on task roles anyway.
    

So directly calling sts:AssumeRole on arbitrary task roles with the instance creds normally fails due to the _trust policy_ (and often IAM permission) barrier.

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

![Alt text](/assets/img/ecscape/agent_introspection.png)

The fact that a container could access the agent’s introspection API is itself a minor isolation gap. Normally, that API might be bound to localhost or a unix socket, but if it’s on the link-local and the iptables aren’t filtering it out, a container could reach it. This is a smaller part of the exploit chain, but highlights how a single oversight can aid an attacker.

Armed with the identifiers, the attacker is ready to masquerade as the agent.

### **Step 4: Forge & Sign the ACS WebSocket (Impersonating the Agent)**

Using:

*   **Poll (ACS) endpoint URL** from Step 2 (e.g. https://ecs-a-1..amazonaws.com/ws – treat as opaque).
    
*   **Identifiers / metadata** from Step 3:
    
    *   agentHash (build fingerprint)
        
    *   agentVersion (e.g. 1.79.0)
        
    *   clusterArn
        
    *   containerInstanceArn
        
    *   dockerVersion (e.g. 20.10.24)
        
    *   protocolVersion (e.g. 1)
        
    *   initial seqNum (e.g. 1)
        
    *   sendCredentials=true (flag to receive credential payloads)
        

You construct a **WebSocket URL** like:

```
wss://ecs-a-1.<region>.amazonaws.com/ws?
  agentHash=<agent-hash>&
  agentVersion=<agent-version>&
  clusterArn=arn:aws:ecs:<region>:<account-id>:cluster/<cluster-name>&
  containerInstanceArn=arn:aws:ecs:<region>:<account-id>:container-instance/<instance-uuid>&
  dockerVersion=<docker-version>&
  protocolVersion=<protocol-version>&
  seqNum=1&
  sendCredentials=true
```

This request must be SigV4‑signed using the stolen instance profile credentials—treat the WebSocket upgrade exactly like a signed HTTPS GET. Those credentials must include (via their IAM policy) permission for at least ecs:Poll (and typically ecs:DiscoverPollEndpoint); without ecs:Poll the control plane will reject the agent channel connection.

I added the query parameter sendCredentials=true to the URL - this is the magic flag that tells the ACS (Agent Communication Service) that, upon connecting, the agent is interested in receiving IAM credential payloads for all tasks. 

With the signing complete (including proper AWS date headers, authorization header, etc.), I initiated the WebSocket connection. Thanks to the correct SigV4 auth and the correct identifiers in place, the backend accepted my connection as if I were the legitimate ECS agent on that container instance. From AWS’s perspective, my process was now just another **(authorized) agent** connecting from that instance.

It’s important to note: the ECS backend did not immediately invalidate the real agent’s session. In fact, I ended up with two concurrent connections for the same container instance - one was the real agent, and one was my impersonating session. The control plane effectively **broadcasted** messages to both connections. (Had AWS limited it to one connection at a time, my exploit might have knocked the real agent offline, which could raise flags. But here, I could stay stealthy, just eavesdropping.)

### **Step 5: Harvest All Task Role Credentials from ACS**

With the forged WebSocket live, you’re now riding the same multiplexed ACS stream the real ECS agent uses. Over this channel the **ECS control plane** continuously pushes structured messages: heartbeats (keep‑alive + sequencing), task state directives (start/stop/update), telemetry, and **IamRoleCredentials** payloads.

**Important clarification:** The _ECS service principal_ (ecs-tasks.amazonaws.com) is the actor that performs sts:AssumeRole for each task role (and execution role, if present). The agent never calls STS itself. Instead, ECS _assumes the role on your behalf_, obtains a temporary credential set, then **delivers (moves) those credentials down to the agent** via ACS. The agent just caches them in memory and serves the task role creds through the per‑task metadata/credentials endpoint; execution role creds stay internal.

Because your forged session included the sendCredentials=true flag and authenticated as the correct container instance, the control plane pushes an IamRoleCredentials message for every currently running task that has a task role. Each message you observe includes the task’s ARN (so you can map to the workload), the IAM role ARN, a credentials UUID (later used in the metadata relative URI), the temporary key trio (AccessKeyId, SecretAccessKey, SessionToken), an expiration timestamp, and a role type indicator (application vs. execution). If there are, say, five tasks with roles on that host, you immediately harvest five distinct credential sets. One belongs to your compromised task—irrelevant—but the others represent lateral escalation paths.

![Alt text](/assets/img/ecscape/hijacked_creds.png)

At this moment, per‑task IAM isolation on that EC2 host is effectively gone: a single low‑privileged container has acquired all co‑resident task role credentials. In realistic environments those might include a backup service (broad S3/database rights), a deployer (CloudFormation / IAM modification rights), or a secrets fetcher.

Your forged channel remains stealthy because you also mimic the agent’s acknowledgement pattern (incrementing sequence numbers, timely ACKs). ECS allows concurrent authenticated sessions for the same container instance; the real agent keeps operating normally and continues receiving the same credential messages. From the control plane’s perspective nothing appears anomalous—just another session delivering and acknowledging tasks and credentials.

**CloudTrail visibility:**

*   The API calls you made to establish the forged channel (e.g. ecs:DiscoverPollEndpoint, the long‑poll / WebSocket authenticated under ecs:Poll) appear as actions by the **instance profile**.
    
*   Any _subsequent AWS API calls_ you perform with stolen task credentials show up as those _task role sessions_ (task ARN embedded in the session context). That’s your primary detection surface: a task role being used for operations it normally doesn’t perform, at unusual times, or with abnormal geographic or service access patterns. Merely receiving credential messages over ACS produces no separate CloudTrail event.
    

**Limitations / nuances:** Tasks without a task role obviously yield no credentials. Tasks started later will generate new credential messages you automatically capture as long as your forged channel persists. Execution role credentials (if present) are also pushed and can be harvested, but they typically grant operational capabilities (ECR image pulls, logs, secrets retrieval) rather than broad business data access; still, they may chain with other permissions.

**Summary:** ECS centralizes AssumeRole in the control plane, then “moves” (delivers) those ephemeral credentials to the on‑host agent, relying on the secrecy of that upstream channel plus local metadata scoping. By impersonating the agent’s upstream identity, ECScape collapses that trust model: one compromised container passively collects every other task’s IAM application role credentials on the same EC2 instance and can immediately act with their privileges.

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
        
for example:
![Alt text](/assets/img/ecscape/task_manifest.png)

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

From a researcher’s perspective, ECScape was a deep dive into how ECS stitches together control‑plane role assumption, on‑host credential delivery, and container isolation. The core lesson: **treat each container (or task) as already compromise‑prone and rigorously constrain its blast radius.** AWS’s abstractions (task roles, execution roles, metadata endpoints) are powerful, but when multiple tasks with different privilege levels share an EC2 host, their security is coupled through the agent channel and the instance profile.

As the ecosystem trends toward stronger isolation models (e.g. Fargate’s per‑task microVM, hardened sandboxing, confidential computing), this specific class of lateral credential harvesting becomes harder. Today, many environments still co‑locate heterogeneous workloads on EC2 capacity, so understanding the _design boundaries_ - not just traditional “vulnerabilities”—is critical.

ECScape illustrates how the boundary between _misconfiguration_, _design trade‑off_, and _exploit chain_ can blur. Defense in depth matters: blocking unnecessary IMDS access, enforcing least‑privilege IAM, isolating high‑value tasks, monitoring for anomalous task role usage, and segmenting workloads by trust level each represent a break point that would have disrupted this chain.

Ultimately, improving security here is a shared responsibility: customers harden deployment patterns; providers continue to refine isolation primitives and credential delivery mechanisms. Shining light on these mechanics enables more informed risk decisions and better monitoring.

Thank you for reading this deep dive. If you have similar experiences or thoughts on ECS security, feel free to share! By shining a light on this mechanism, I hope others will secure their ECS deployments or at least monitor them more vigilantly.