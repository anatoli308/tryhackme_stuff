ou made it through the Cyphira Audit. Let's recap what we covered, map it to industry frameworks, and set you up for what comes next.
Mapping to Industry Frameworks

The techniques and findings from this room align with several widely adopted security frameworks. This mapping helps you communicate your reconnaissance results in language that security leaders, auditors, and compliance teams already understand.

(Adversarial Threat Landscape for Systems)

is the primary framework for -specific threats. Here is how this room maps:
Room Content 	Technique ID 	Technique Name
Shodan and GitHub dorks for infrastructure 	AML.T0000 	Active Scanning
Locating model registries and artifacts through unsecured APIs 	AML.T0048 	Discover Artifacts
Finding exposed HF tokens and 	AML.T0040 	Supply Chain Compromise
Enumerating configs and schema compatibility 	AML.T0069 	Discover System Information
All reconnaissance activities collectively 	AML.TA0002 	Reconnaissance (Tactic)

ATT&CK (Enterprise)

Traditional ATT&CK techniques also apply because reconnaissance uses many of the same methods as conventional network assessment:
Room Content 	ATT&CK Technique ID 	Technique Name
Port scanning for -specific services 	T1046 	Network Service Scanning
Extracting deployment topology from metrics and metadata 	T1592 	Gather Victim Host Information
Probing for unauthenticated management interfaces 	T1595.002 	Vulnerability Scanning
Collecting infrastructure intelligence before engagement 	TA0043 	Reconnaissance (Tactic)

Top 10 for Applications (2025)

Several risks directly relate to findings from this room:
Room Finding 	ID 	Risk Name
Exposed MLflow servers, Jupyter notebooks, unauthenticated APIs 	LLM05 	Improper Output Handling (relates to exposed metadata and information leakage through responses)
Model artifacts downloadable from unsecured registries 	LLM06 	Excessive Agency (relates to model access without proper authorisation controls)
Leaked HF tokens, , poisoned model files from public hubs 	LLM03 	Training / Supply Chain Vulnerabilities
Default credentials, missing authentication on MLflow and Kubeflow 	LLM10 	Model Theft (reconnaissance enables direct model exfiltration)

Risk Management Framework ( RMF 1.0)

RMF organises risk into four functions: Govern, Map, Measure, and Manage. This room's content falls primarily under the Map function:

    Map 1.1: system components and their interactions are identified. This is exactly what Tasks 2 through 4 accomplish. You cannot assess risk in infrastructure you have not discovered.
    Map 1.5: Potential risks of the system are assessed. The attack surface mapping in Task 5 directly supports this. Identifying misconfigurations, exposed registries, and supply chain risks is risk assessment at the infrastructure layer.
    Map 3.2: Risks related to third-party resources are identified. The supply chain reconnaissance in Task 5 (Hugging Face tokens, PyTorch Hub dependencies, public model registries) maps here.
    Measure 2.6: Processes exist to determine whether systems are functioning as intended. The metrics and debug interface enumeration from Task 4 support this, as unexpected exposed endpoints indicate systems not functioning as intended from a security perspective.

Cybersecurity Framework ( 2.0)

The room's content aligns with 2.0's Identify function:

    ID.AM (Asset Management): Discovering and inventorying infrastructure components across the network. This is the core purpose of the entire room.
    ID.RA (Risk Assessment): Mapping the attack surface and identifying misconfigurations that introduce risk.

What Comes Next

You now know how to find and enumerate components. The next room, Threat Modelling Assessment, picks up where this room ends.

In the Threat Modelling Assessment room, you take the reconnaissance output you built here and assess the security posture of what you found. Which findings represent actual vulnerabilities? What is the impact if each one is exploited? What mitigations should the organisation prioritise?

Every deployment you cannot find is one you cannot protect. The gap between what organisations think they have deployed and what is actually exposed on their network is where attackers operate. You now have the skills to close that gap.
Answer the questions below

All done!
How likely are you to recommend this room to others?
1
2

In previous tasks, we identified components in the network, determined which framework each component runs on, and extracted metadata from their APIs. Those are individual findings. This task is about connecting them.

    A single exposed MLflow server is a finding.
    The difference between a list of findings and an attack surface map is the connections between them.

How Expands the Traditional Attack Surface

In Task 2, we catalogued 14 components across 20+ ports. Compare that to a traditional web application, which adds roughly 5 ports to a network, but the port count alone is not the full picture.

These services constantly talk to each other. The inference server pulls features from the vector database. The orchestration platform pushes model updates to the registry. Jupyter notebooks connect to everything. scrapes metrics from every service. If one component binds to 0.0.0.0 instead of 127.0.0.1, the entire internal mesh becomes reachable.

The security perimeter for an deployment is not the external . It extends deep into the internal communication pathways between these services. Overly permissive network policies and the absence of between data-hungry components are the norm, not the exception.

AI Infra shopping
Platform Misconfigurations That Attackers Map

Every major platform has documented misconfigurations that turn routine deployments into reconnaissance targets.

MLflow shipped without authentication by default before version 2.x.

    Even after authentication was added, -2026-2635 revealed that MLflow's basic_auth.ini file contained hardcoded default credentials.
    Attackers running mass port scans on port 5000 could authenticate using these defaults.
    CVE-2026-2033 went further: a directory traversal flaw in the artifact handler allowed unauthenticated remote code execution.
    Both scored CVSS 9.8.

Kubeflow dashboards are frequently deployed without OIDC authentication and exposed via a basic Kubernetes LoadBalancer or NodePort.

    An unauthenticated user can access the full Kubeflow interface and spawn Jupyter notebooks, which are attached to Kubernetes service accounts with cluster-level permissions.
    That is a direct path from an open dashboard to container orchestration access.

TorchServe exposes a management API on port 8081 that allows dynamic model registration from arbitrary URLs.

    If that port is accessible, an attacker can instruct the server to download and load a malicious .mar (Model Archive) file from an external server.
    TorchServe executes initialisation code during model loading, so loading a crafted archive achieves remote code execution.

SageMaker notebooks with DirectInternetAccess: Enabled accept inbound connections from the internet.

    A 2024 cloud security report found that 82% of organisations using SageMaker had at least one notebook configured this way.

Model Registries: The Highest-Value Target

We covered MLflow enumeration in Task 4. Now let's talk about why an unsecured registry is the single most damaging reconnaissance finding.

A registry does not just store model files. It stores the complete lineage:

    Model names
    Version history
    Stage labels (staging, production, archived)
    Creation timestamps
    Run IDs linking back to full training metadata
    Artifact URIs revealing internal cloud storage paths
    User ID of every contributor

One open registry maps the entire ML product portfolio. IBM X-Force documented the exploitation pattern:

    An attacker finds MLflow credentials in a Jupyter notebook
    They run MLOKit against the registry
    Then exfiltrate every model artifact

The registry is the map that tells the attacker where everything else is stored.
Supply Chain Reconnaissance

AI systems depend heavily on external resources, and those dependencies are discoverable during reconnaissance.

Hugging Face tokens appear in GitHub repositories via simple dorks: filename:.env HF_TOKEN.

    They appear in .env files, CI/CD pipeline logs, and Kubernetes secrets.
    A compromised token grants read and write access to the organisation's private models and datasets on the Hugging Face platform.

Dependency confusion applies to ML pipelines just as it applies to traditional software.

    ML projects have large requirements.txt files with internal package names.
    If an internal package like company-data-utils is not registered on PyPI, an attacker can register it there.
    Kubeflow pipelines that build containers at training time pull packages live, so a typosquatted or misconfigured package can execute code inside the training cluster.

Model download sources are identifiable during reconnaissance.

    If the organisation pulls models from the Hugging Face Hub or the PyTorch Hub, the download paths are visible in configuration files, notebook cells, and container build logs.
    An attacker who can inject a malicious model into an upstream source (or replace one via a compromised HF token) poisons the entire supply chain.

MITRE ATLAS Mapping

Everything we have covered in this room maps to the MITRE ATLAS framework. ATLAS is modelled after ATT&CK but specifically covers adversarial threats to AI and ML systems. It contains 15 tactics, 66 techniques, and 46 sub-techniques as of late 2025.

Here is how the room's content connects:
Room Content 	ATLAS Technique
Port scanning for AI services, probing endpoints 	AML.T0006 (Active Scanning)
Locating model registries and training artifacts through unsecured APIs 	AML.T0007 (Discover ML Artifacts)
Finding exposed HF tokens and poisoned dependencies 	AML.T0010 (ML Supply Chain Compromise)
Enumerating LLM configurations and API compatibility 	AML.T0014 (Discover ML Model Family)
All of the above, collectively 	AML.TA0002 (Reconnaissance tactic)

ATLAS techniques are not just labels. They provide a shared vocabulary for communicating findings. When you write a reconnaissance report, mapping each finding to an ATLAS technique ID tells the reader exactly what category of activity you performed and what risk it represents.
Case Study: ShadowRay Campaign (CVE-2023-48022)

The ShadowRay campaign (opens in new tab) is the clearest example of how reconnaissance of a single AI component cascades into full infrastructure compromise.

Ray's Job Submission API on port 8265 shipped without authentication by design. Anyscale, the company behind Ray, maintained that Ray should run only within trusted network boundaries and that the lack of authentication was an intentional feature, not a bug. They disputed the CVE. Attackers disagreed.

    Using Shodan, they identified over 230,000 publicly exposed Ray dashboards. Once they found an open dashboard, they submitted malicious jobs through /api/jobs/ containing multi-stage payloads.
    The first stage performed reconnaissance on the compromised host: reading /etc/passwd to enumerate users and running printenv to dump environment variables and harvest tokens and other cloud credentials. Using those stolen credentials, the attackers pivoted laterally across cloud infrastructure.
    The primary objective was resource theft. The attackers hijacked GPU compute nodes and deployed XMRig cryptocurrency miners. They capped usage at 60% and disguised their processes as legitimate kernel workers to avoid detection.

The ShadowRay 2.0 variant, active from late 2025, added significant sophistication.

    Attackers used LLMs to generate adaptable malware payloads and established through hidden cron jobs and systemd services.
    They hosted their payloads on GitLab and, when those repositories were taken down, migrated them to GitHub within days.
    The campaign also deployed sockstress (a exhaustion tool) against production websites, turning the operation into a multi-purpose botnet.

Why this matters for this room: the entire ShadowRay chain started with reconnaissance. Finding an exposed dashboard (Task 2). Confirming it was Ray (Task 3). The was unauthenticated and ready for job submission (Task 4). One exposed component, discovered through the same techniques we have been practising, led to credential theft, lateral movement, and large-scale resource hijacking.
Agent Exercise

Now let's connect your findings to the bigger picture. Open the Cyphira Threat Mapper agent.

You have spent three tasks discovering, fingerprinting, and enumerating services on the Cyphira network. You have a list of findings: exposed services, model metadata, artifact URIs, user , cleartext credentials, and supply-chain dependencies. This exercise asks you to map those findings to techniques and connect them to real-world incidents.

Step 1: Review your findings.

    Ask the agent to summarise the Cyphira findings from Tasks 2-4.
    It will present a consolidated list of everything discovered so far.
    Make sure it matches what you found.

Step 2: Classify the findings.

    The agent will present scenarios one by one.
    Each scenario describes a specific reconnaissance activity from the Cyphira audit.
    Your job: identify which technique ID applies to each scenario.
        Use the mapping table from the task content as your reference.

Test your understanding by answering the questions below
Answer the questions below

The Cyphira Jupyter notebook at 10.10.45.20 contains a Hugging Face token (hf_kR7mXpQvL9nJwT2yBcDfAeGh8iKlMnOp). The internal-kb-embedder model on MLflow references sentence-transformers/all-MiniLM-L6-v2 as its base model. What ATLAS technique ID covers the risk of these exposed supply chain dependencies?

You scanned the Cyphira subnet with nmap, probed endpoints with curl, and extracted metadata from MLflow APIs. All of these activities fall under one overarching ATLAS tactic. What is its ID?

Uh-oh! The answer you provided may not be in English. Please review it and try again.