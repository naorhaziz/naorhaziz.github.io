---
title: "Under the Hood of Amazon ECS on EC2: Agents, IAM Roles, and Task Isolation"
layout: post
date: 2025-07-16 16:00:00 +0300
categories: [aws, ecs, security, cloud]
tags: [ecs, iam, container]
image: /assets/img/under-the-hood-of-amazon-ecs/amazon-ecs.png
---

When running containers on Amazon ECS using EC2 instances, there's a lot happening under the hood on each host. Understanding these internals is crucial for operating ECS securely. In this first part of our deep‑dive, we’ll explore how ECS on EC2 works – focusing on the **ECS agent**, the IAM roles and credential delivery mechanism, and where the boundaries (and lack thereof) lie between tasks on the same host. _(In Part 2, we'll leverage this knowledge to examine a real‑world cross‑task credential exposure scenario in ECS.)_
[ECScape – Understanding IAM Privilege Boundaries in Amazon ECS](/posts/ecscape-iam-privilege-boundaries-in-ecs/)

> **Note on Security Boundaries:** This deep‑dive focuses on known characteristics of ECS on EC2 rather than disclosing a new vulnerability. On the EC2 launch type, multiple tasks share the same host kernel and resources. This design provides flexibility but means that untrusted or low‑privilege tasks should not be co‑located with high‑privilege tasks. AWS offers **Fargate** – where each task runs in its own micro‑VM – for teams needing stronger isolation. In July 2025 we followed AWS’s responsible disclosure program to share our findings. AWS confirmed this behaviour is a **design consideration**, not a vulnerability, and subsequently updated their [task‑IAM documentation](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html) and a [security‑considerations blog post](https://aws.amazon.com/blogs/security/security-considerations-for-running-containers-on-amazon-ecs/).

**TL;DR**
---------

*   On EC2, ECS tasks share the same host instance; on Fargate, each task executes in a dedicated VM. Different isolation model, different risk.

*   A single, privileged **ECS agent** on each host registers the node, talks to AWS, starts/stops containers, and hands out IAM creds.
    
*   AWS (not the agent) assumes each task’s IAM role, then puhshes those short‑lived keys down to the agent, which serves them at 169.254.170.2.
    
*   The agent’s own identity comes from the EC2 **instance role** via IMDS. If those keys leak, someone can impersonate the agent.
    
*   Per‑task isolation depends on namespaces, iptables, and the agent behaving correctly—containers aren’t a hard security boundary on EC2.

**Recommended Primers**

If any of the acronyms below feel rusty, a quick skim of these docs will make the deep-dive smoother:

*   [AWS Identity & Access Management (IAM)](https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html) 
    
*   [Amazon EC2 basics](https://docs.aws.amazon.com/ec2/index.html)
    
*   Docker fundamentals
    
*   [IMDS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
    
*   [Amazon ECS overview](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/Welcome.html) 
    
*   [Signature Version 4 (SigV4)](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
    
*   [AWS Fargate](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/AWS_Fargate.html)

**ECS Launch Types: EC2 vs. Fargate**
-------------------------------------

ECS supports three launch models for running containers: **EC2**, **Fargate**, and **ECS Anywhere**.
With the **EC2 launch type**, you manage a cluster of your own EC2 instances that run the ECS agent and host your containers.
In contrast, **Fargate** is a managed option where AWS runs tasks in isolation without exposing the underlying server to you.
**ECS Anywhere** allows you to run ECS tasks on your own on-premises infrastructure or other compute environments using the ECS agent.

**Why does this matter?** In Fargate, each task gets its **micro-VM** and does _not_ share the kernel, CPU, memory, or network interface with other tasks. That design gives you a strong, hypervisor‑level isolation boundary out of the box.
By contrast, when you run ECS tasks on **EC2 instances**, **multiple containers live side‑by‑side on the same host OS**. They share the Linux kernel and other system resources, blurring isolation boundaries.

Understanding how the ECS agent manages containers and credentials on EC2 instances will highlight where those boundaries exist and where they might break down.

![Alt text](/assets/img/under-the-hood-of-amazon-ecs/ec2-vs-fargate.jpg)

**Meet the ECS Agent**
----------------------

When you launch an ECS cluster on EC2, each EC2 instance (called a _container instance_ in ECS terminology) runs a process called the **ECS agent**. The agent is essentially a specialized **Docker/Container orchestrator** that connects your EC2 host to the ECS control plane. AWS provides the agent as an open-source application (it even runs as a privileged Docker container itself). Its main responsibilities include:

*   **Cluster Registration & Heartbeat:** When the EC2 instance starts, the agent registers itself with your ECS cluster using the cluster’s name/ARN. It maintains a long-lived connection (or long-poll) with the ECS service to report status and retrieve updates (like new tasks to run).
    
*   **Task Lifecycle Management:** Upon receiving instructions to start containers (tasks), the agent will pull the required images (integrating with Amazon ECR if needed), create and run containers via the local Docker daemon, and later stop or clean them up as instructed. It also reports back the status of tasks (e.g., RUNNING, STOPPED, exit codes).
    
*   **Networking Setup:** The agent sets up network interfaces and rules for containers. In the **awsvpc network mode**, it will attach a dedicated Elastic Network Interface (ENI) to the task and configure the container’s network namespace with that ENI. In **bridge/host modes**, the agent configures local iptables rules to route task traffic and protect the metadata endpoints.
    
*   **Logs and Metrics Forwarding:** If your task is configured to use CloudWatch Logs or other logging (e.g., FireLens) or to send task metrics, the agent helps facilitate that. For example, for CloudWatch Logs it might request a temporary token (using an IAM **execution role**) and forward container logs, without exposing that token to the container.
    
*   **Credential Delivery to Tasks:** _This is one of the most important roles of the agent._ When you specify an IAM **task role** for your ECS task (so the application can call AWS APIs), the ECS agent ensures the task can obtain temporary credentials for that role. It does so by **receiving the credentials from the ECS control plane** and then exposing them via a local HTTP endpoint accessible only to that task. We’ll dive deeper into how this works shortly.

Think of the ECS agent as a middleman between your containers and the AWS ECS control plane, with the power to orchestrate containers on the host and hand out credentials or resources to them as needed. Because it runs with elevated privileges on the host, it has access to the host’s resources that normal containers do not.

**Note:** The ECS agent typically runs in the **host network mode**, meaning it shares the host’s network stack. This is by design, to allow the agent to communicate with AWS endpoints and manage network namespaces for tasks. A side effect is that you (as the ops team) can implement network rules on the host that apply to all containers – for example, blocking certain external access from tasks (more on this later).

![Alt text](/assets/img/under-the-hood-of-amazon-ecs/ecs-agent-diagram.png)

**The EC2 Instance Role and IMDS: Credentials for the Agent**
-------------------------------------------------------------

Every ECS EC2 instance should be launched with an **IAM role** attached to it (as an EC2 Instance Profile). A common default is an IAM role named **ecsInstanceRole**, which comes with a managed policy **AmazonEC2ContainerServiceforEC2Role**. 

![Alt text](/assets/img/under-the-hood-of-amazon-ecs/ecs-instance-role.png)

This **instance role** is used by the ECS agent to call AWS APIs on your behalf. It grants only the limited permissions needed for the agent’s operations – for example:

*   **ECS control plane:** Permissions like ecs:RegisterContainerInstance, ecs:DiscoverPollEndpoint, ecs:Poll, ecs:Submit\* (to register the instance, poll for tasks/updates, and submit status).
    
*   **ECR image pulls:** ecr:GetAuthorizationToken, ecr:BatchGetImage so the agent can fetch private Docker images from ECR if your tasks need them.
    
*   **CloudWatch Logs/Telemetry:** Permissions such as logs:CreateLogStream, logs:PutLogEvents if using CloudWatch, and others to support sending metrics.
    

Notably, the **instance role is separate from any roles you assign to your tasks** – it’s only meant for the agent’s infrastructure duties, not for application-level API calls. In fact, the instance role typically does **not** include privileges like generic sts:AssumeRole or access to your application data by default.

**How does the ECS agent get the credentials for this role?** It uses the standard EC2 **Instance Metadata Service (IMDS)**. On every EC2 instance, there is a special HTTP endpoint http://169.254.169.254/latest/meta-data/iam/security-credentials/ which will return temporary AWS credentials (Access Key, Secret Key, Session Token) for the IAM role attached to that instance. The ECS agent, running on the host, queries this metadata endpoint regularly to get and refresh its own credentials (in this case, for the ecsInstanceRole). It then uses those credentials to authenticate to ECS and other services.

![Alt text](/assets/img/under-the-hood-of-amazon-ecs/imds-role.png)

**Agent Registration: Announcing the Container Instance**
---------------------------------------------------------

When an ECS‑optimised EC2 host boots, the **ECS agent** (running as a privileged Docker container) must introduce itself to the control plane. It does this with a single API call - **RegisterContainerInstance** - signed with the **instance‑role** credentials and authorised by the ecs:RegisterContainerInstance action.

The request body contains:
*   **clusterArn** – which cluster to join    
*   **EC2 instance‑identity document** – AMI ID, instance ID, region, etc.
*   **resources** – CPU, memory, GPU, ENI capacity
*   **versionInfo** – agent build hash + Docker version

If the signature checks out, ECS accepts the host and returns a **containerInstanceArn** - a unique ID the agent will use later.

After this action is completed, the newly registered container instance will appear on the AWS console:
![Alt text](/assets/img/under-the-hood-of-amazon-ecs/container-instance.png)

**Authorization Flow: From DiscoverPollEndpoint to a SigV4‑Signed ACS WebSocket**
----------------------------------------------------------------------------------

The **ECS agent authenticates itself to the control plane with exactly two IAM permissions** on the _instance role_:

* **ecs:DiscoverPollEndpoint** - Returns a short‑lived hostname for ACS (command channel) and TCS (telemetry).
* **ecs:Poll** - Authorises the long‑lived WebSocket upgrade that carries tasks, **IamRoleCredentials**, ACKs, etc.

If a principal has those two actions – nothing more – it can act as _the_ agent for that container instance.

### Step 0 - Instance role credentials

The agent starts by fetching temporary keys from IMDS for the **instance role** (usually ecsInstanceRole). Those credentials sign every subsequent control‑plane request.

### Step 1 - DiscoverPollEndpoint
The agent calls the **DiscoverPollEndpoint** API using the ecs:DiscoverPollEndpoint permission.
This API provides the ECS agent with the current control and telemetry endpoints. In some cases, it may also include a serviceConnectEndpoint, which is used by the service connect proxy (not by the ECS agent itself).
Typical response:
```
{
  "endpoint":           "https://ecs-a-1.us-east-1.amazonaws.com",
  "telemetryEndpoint":  "https://ecs-t-1.us-east-1.amazonaws.com",
  "serviceConnectEndpoint":  "https://ecs-sc-1.us-east-1.amazonaws.com",
}
```
Note: These endpoints are time-scoped and may change over time. The values returned are not guaranteed to remain constant and may vary for reasons such as regional load balancing.

![Alt text](/assets/img/under-the-hood-of-amazon-ecs/discover-poll-endpoint.png)

### Step 2 - Build WebSocket URL ("enrichment")

The agent expands the bare hostname into a query‑rich URL:
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

Every parameter becomes part of the **Canonical Request** in SigV4; altering one byte breaks the signature.

![Alt text](/assets/img/under-the-hood-of-amazon-ecs/agent-code-acs-url.jpg)


### Step 3 - SigV4 upgrade (ecs:Poll)

The agent performs an HTTPS GET with Upgrade: websocket plus standard SigV4 headers. If IAM allows ecs:Poll, the control plane answers **101 Switching Protocols**. The socket is now live, and the **ACS protocol** rides over it.

![Alt text](/assets/img/under-the-hood-of-amazon-ecs/poll-sigv4.png)

**ACS Protocol Deep Dive**
--------------------------
**Agent Communication Service (ACS)** is Amazon's proprietary, **undocumented** real-time messaging protocol that operates over WebSocket connections. Unlike REST APIs, ACS uses **persistent bidirectional streams** of JSON-framed messages for near-instantaneous task lifecycle management and credential distribution.

### Protocol Architecture

The protocol operates on a **push-pull model**: AWS's control plane pushes desired state changes down to agents, while agents acknowledge receipt and report actual state back up. This creates a **eventually consistent** distributed system where the control plane maintains authoritative state, but agents operate autonomously during network partitions.

**Message Flow Pattern:**
```
Control Plane → Agent: "Start task X with these credentials"
Agent → Control Plane: "Acknowledged, task X starting"
Agent → Control Plane: "Task X now running, credentials received"
```

### Key Message Categories

**Task Orchestration Messages:**
*   **PayloadMessage** - The heavyweight carrying complete task definitions, container specifications, and crucially, embedded ExecutionRoleCredentials and RoleCredentials for IAM role assumption
*   **TaskManifestMessage** - Lightweight inventory updates listing which tasks should be running and their desired states
*   **TaskStopVerificationMessage** - Graceful shutdown coordination allowing configurable drain periods

**Credential Management Messages:**
*   **IAMRoleCredentialsMessage** - Dedicated credential delivery distinguishing between TaskExecution (for ECS operations like image pulling) and TaskApplication (for container workloads)
*   **RefreshCredentialsMessage** - Proactive credential rotation before expiration, ensuring long-running tasks never face authentication failures

**Connection Management:**
*   **HeartbeatMessage/HeartbeatAckRequest** - Bidirectional liveness probes detecting network partitions and connection health
*   **CloseMessage** - Graceful connection termination with reason codes like "ConnectionExpired: Reconnect to continue"

### Protocol Evolution

Looking at the AWS SDK source, we can see the protocol has evolved to include **Service Connect endpoints**, indicating Amazon's continued investment in this internal communication channel.

The protocol's undocumented nature means it can evolve rapidly without backward compatibility concerns, allowing Amazon to optimize for performance and security without external API constraints.

**From Instance Role to Task Role: Credential Isolation per Task**
------------------------------------------------------------------

One of the most convenient features of ECS is the ability to assign an **IAM role to a task** (often called the _task role_ or _IAM task role_). This allows the application code running in the container to call AWS APIs (S3, DynamoDB, etc.) without embedding AWS keys in the container image or using long-lived credentials. Each task’s role is specified in the task definition, and different tasks can have different IAM roles. The naive expectation (more on that later) is that **each task should only be able to use its own IAM role’s permissions**, and not access credentials intended for other tasks.

**So how does ECS provide each task with credentials for its role?** The flow works like this:

1.  **Control Plane Assumes the Role:** When a task is about to be launched, the ECS service back-end (the ECS control plane, acting as the principal ecs-tasks.amazonaws.com) will perform an STS AssumeRole operation on the IAM role specified for the task. This yields a set of temporary credentials (let’s call them **TaskCredentials: AccessKey/Secret/Token**) valid for a short duration (usually 1-6 hours).
    
2.  **Credentials Pushed to the ECS Agent:** The ECS control plane then sends these temporary TaskCredentials down to the ECS agent running on the appropriate EC2 instance. This happens over ACS connection using **IAMRoleCredentialsMessage** and **RefreshCredentialsMessage** messages.
    
3.  **Agent Stores and Serves Credentials:** The agent caches these credentials in memory, indexed by an identifier. It then **exposes them via a metadata service** running at 169.254.170.2. When the container for that task starts, the agent injects an environment variable into it: AWS\_CONTAINER\_CREDENTIALS\_RELATIVE\_URI. This is a unique path, such as /v2/credentials/12345678-90ab-cdef-1234-567890abcdef, that the task can query on the special 169.254.170.2 endpoint. For example, inside the container, an AWS SDK will hit http://169.254.170.2/v2/credentials/12345678-... and receive a JSON blob of credentials for that task’s role.
    
4.  **Task Uses Its Credentials:** The container’s application code, using the AWS SDK default provider chain, will automatically pick up those credentials (the SDK knows to query the container credentials URI if present). The task now has the correct IAM privileges as intended, and ideally it never had to know about the underlying instance role at all.

![Alt text](/assets/img/under-the-hood-of-amazon-ecs/credentials-acs.png)
        
This mechanism means each task gets straightforward access to credentials scoped to its IAM role. These credentials are delivered and updated at runtime for automatic consumption by the SDK.
Tasks normally do not see each other’s credentials because:

*   Each credentials payload has a unique UUID and is only delivered to the agent, it’s not stored in a location accessible by other tasks.
    
*   In modern ECS (with awsvpc networking), each task runs in its own network namespace, so it can only reach the 169.254.170.2 endpoint _within that namespace_, which the agent routes to the correct credentials. Tasks shouldn't be able to query the agent for another task’s URI because they can’t even see that other task’s network interface or environment variables.
    
*   Even in bridge network mode, the agent sets up iptables rules to restrict access so that one container can only get its own credentials via the specific URI. But note that by
default the containers can still easily reach the instance metadata service, and thus have access to the agent's credentials and privileges as well as their own.
    
At first glance, this per-task credential scoping is a great security feature. It avoids the historical problem of sharing the instance’s IAM role across all containers. For example, a web app task might have access to a specific S3 bucket, while an admin task on the same host has broader privileges—and the two shouldn’t interfere.

However, it’s important to note that this mechanism doesn’t establish a hard security boundary. The ECS agent ultimately decides which credentials to serve in response to requests at 169.254.170.2. So if an attacker can deploy code to a container and influence the agent (or spoof it), they may be able to fetch credentials not intended for their task. In Part 2, we’ll demonstrate exactly how this can happen.

AWS documentation also explicitly notes that ECS does not treat this isolation as a strict boundary:
* “Task IAM roles allow you to specify IAM permissions for your containers without requiring those permissions to be specified using EC2 instance profiles…”

* “Task credentials have a context of ‘taskArn’ that is attached to the session, so CloudTrail logs show which task the role was used by.”

In theory, this isolates IAM credentials on a per-task basis, which is a great security feature. It avoids the historical problem of sharing the instance’s IAM role among all tasks. Now, a web app container might only have rights to a specific S3 bucket, while a different admin task on the same host might have broader rights - and the two shouldn’t conflict.

**However,** as with any security mechanism, it assumes the controls are working correctly. If there’s any way for a container to break out of its network namespace or trick the agent, those assumptions could fail. Remember that the agent itself ultimately decides “who gets what credentials” when serving that 169.254.170.2 request. If an attacker finds a bug or misconfiguration in that process, they could potentially obtain credentials not meant for them. In Part 2, we will see exactly such a scenario.

**Key Takeaways**
-----------------

1.  **Single Authority on the Host:** The agent registers the EC2 instance, keeps a live control‑plane socket, and orchestrates every container.
    
2.  **Credential Hub:** All task‑role credentials arrive from AWS over the agent’s WebSocket and are cached only in memory.
    
3.  **Network & Metadata Gatekeeper:** The agent wires ENIs, sets iptables, and exposes 169.254.170.2 so each task can fetch _only its own_ keys.
    
4.  **Trust Equals Instance Role:** The control plane trusts the agent because it signs requests with the instance‑role credentials.
    
5.  **Failure Domain:** If the agent or its instance-role credentials are compromised, an attacker may gain access to any task’s credentials on the host, despite the assumed per-task separation.

Now that we’ve covered how ECS on EC2 operates – from the agent and instance roles to task IAM credentials and isolation boundaries – we have the necessary background to understand a fascinating **cross‑task credential exposure scenario**. In **Part 2**, we’ll explore **“ECScape,”** a technique where a malicious container on ECS can impersonate the ECS agent and retrieve credentials intended for other tasks on the same host. This isn’t a vulnerability in AWS but a design characteristic of the EC2 launch type that highlights the importance of isolation and least privilege. Stay tuned!

➡️ **Continue to Part 2:** [ECScape – Understanding IAM Privilege Boundaries in Amazon ECS](/posts/ecscape-iam-privilege-boundaries-in-ecs/)

## Responsible Disclosure and AWS Collaboration

In July 2025 our team reported the cross‑task credential exposure described in this series to AWS through their coordinated disclosure program. AWS reviewed our research and determined that the behaviour is a **design consideration** of ECS on EC2 rather than a security vulnerability. They expressed appreciation for our work and collaborated to improve public documentation. AWS updated guidance on [task IAM roles](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html) and updated a [security considerations blog post](https://aws.amazon.com/blogs/security/security-considerations-for-running-containers-on-amazon-ecs/) that explicitly states that tasks running on the same EC2 instance may potentially access credentials belonging to other tasks, recommending the use of Fargate for stronger isolation and careful monitoring of task role usage via CloudTrail.

By sharing our findings we hope to help ECS users design secure architectures and make informed decisions about launch types and isolation boundaries, and to demonstrate our commitment to customer education and partnership with AWS.
