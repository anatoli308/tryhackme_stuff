Retrieval-Augmented Generation () allows language models to use external documents when answering questions. Instead of relying solely on , a system retrieves relevant information at inference time and provides it as additional context before generating a response. This improves accuracy and freshness, but it also changes how trust works in the system. This room covers how systems work, where their unique security risks appear, and how attackers exploit retrieval, context injection, and trust boundaries to manipulate model outputs.

traditional vs rag systems
Learning Objectives

By completing this room, you will be able to:

    Describe how systems work at a high level
    Explain why retrieval introduces inference-time risks
    Identify concrete security issues specific to
    Understand why traditional security assumptions do not fully apply

Prerequisites

Before starting this room, you should be familiar with:

    What a Large Language Model () is
    How prompts and responses work in systems
    Basic security concepts such as trust boundaries and data

No prior experience is required.
Answer the questions below

I understand the learning objectives and am ready to learn about RAG security fundamentals!

 systems introduce several new areas where security failures can occur. Unlike traditional applications, external data is not just stored — it directly influences model reasoning at inference time.

The main -specific attack surfaces are:

    Document ingestion: Untrusted, outdated, or malicious documents can enter the system if validation is weak.
    generation: Text is converted into numerical vectors, making intent and safety harder to inspect manually.
    Similarity-based retrieval: Documents are selected by semantic relevance, not correctness, trust, or safety.
    Context injection: Retrieved documents are injected directly into the model’s before generation.

Each stage increases the system’s exposure to manipulation.

Threat modelling and understanding RAG attack surfaces
1. Document Ingestion

systems often ingest data from shared drives, wikis, or automated feeds. If validation is weak, untrusted or malicious documents can enter the knowledge base and become treated as trusted information.
2. Generation

Ingested documents are converted into embeddings. This process removes context such as authorship or approval status, making malicious and legitimate content appear equally valid.
3. Similarity-Based Retrieval

Documents are retrieved based on semantic similarity, not trust or intent. Attackers only need their content to “sound relevant” to influence retrieval results.
4. Context Injection

Retrieved documents are injected directly into the model’s prompt. The model cannot distinguish instructions from data, treating all retrieved content as trusted context.
Why Retrieval Is the Highest-Risk Component

Retrieval happens automatically and invisibly to the user. The language model:

    Cannot see where the documents came from
    Cannot verify document intent
    Cannot distinguish instructions from data

Once content is retrieved, it is treated as trusted background information. This makes retrieval one of the most security-critical components in a system.
Answer the questions below

Which RAG stage introduces the largest indirect attack surface?

What component is lost during embedding generation that affects security?
In a deployment, the application provides retrieved content alongside user input. The model follows the structure of the input it receives, but it does not independently verify whether the retrieved information is correct, safe, or appropriate. This introduces specific security risks.

Because retrieval happens at inference time, malicious or misleading documents can influence responses without retraining the model. This is known as inference-time . Retrieved content can also manipulate context by framing information in ways that alter the model's behaviour. In some cases, retrieved documents may contain instruction-like text that overrides system intent, even though the prompt itself was not modified. Securing a system requires controlling how external data is selected, injected, and constrained during retrieval.

To understand where these risks appear, you need to know how a system is structured.

Internal components of the RAG system
Core Components of a System

A typical system includes the following parts:

    Model: This model converts text into vectors; both user queries and documents go through this process.
    Vector Store: The vector store stores document embeddings; these embeddings represent the meaning of text as numerical values, enabling similarity comparisons.
    Retriever: The retriever is responsible for finding relevant documents based on a user’s query, it uses similarity matching rather than exact keywords.
    Language Model (): The language model generates the final response using the retrieved documents as context.

How Data Flows Through

A simplified workflow looks like this:

    The user submits a query
    The query is converted into an
    The vector store searches for similar document embeddings
    Top matching documents are retrieved
    Retrieved content is injected into the ’s context
    The generates a response

At no point does the model verify whether the retrieved data is correct or safe.
Where Security Risks Concentrate

Although every component matters, risk concentrates in three areas:

    Ingestion: Malicious documents entering the system
    Retrieval: Poisoned documents ranking highly
    Context injection: Retrieved content influencing generation

These areas will be the focus of the practical tasks later in the room.
Answer the questions below

What numerical representation is used to capture the meaning of text in RAG systems?

Which component selects the documents for the LLM?

Retrieval abuse is a -specific attack technique in which unintended or malicious documents influence model output via retrieval. This does not always require active manipulation by an attacker. In many cases, a malicious or misleading document is already present in the knowledge base and is retrieved automatically during normal queries. Unlike traditional prompt injection, the attacker does not interact directly with the model’s prompt. Instead, they influence what data the retriever selects.
Active vs Passive Retrieval Abuse

Retrieval abuse can occur in two common ways:

    Passive poisoning: Malicious content is ingested once and left in the knowledge base. The attacker waits for normal queries to retrieve it.
    Active manipulation: Content is deliberately crafted to rank highly for common or sensitive queries.

In both cases, the attacker does not need continuous access to the system.
How Context Manipulation Works

In systems, retrieved documents are injected into the model’s before generation.

Problems arise when a retrieved document:

    Contains misleading or false information
    Includes hidden instructions framed as documentation

Retrieval selects documents based on semantic relevance, not intent or safety. If a document ranks highly, it is included in the context used for generation.
Retrieval Abuse explainedWhy the Model Cannot Defend Itself

From the model’s perspective, all retrieved content looks the same, because the model:

    Cannot verify document intent
    Cannot see retrieval rankings
    Cannot reliably distinguish instructions from data

Once content appears in the , it is treated as authoritative input due to placement, not because it has been verified. This is a design limitation, not a configuration mistake.
Why Retrieval Abuse Is Difficult to Detect

Retrieval abuse is difficult to spot because:

    Outputs may appear logical and well-structured
    No visible prompt injection is present
    Logs may only show “relevant documents retrieved.”

From the system’s point of view, retrieval is working as designed.
Security Impact of Context Manipulation

By manipulating retrieval, attackers can:

    Influence responses without modifying prompts
    Indirectly override system intent
    Introduce subtle misinformation or unsafe guidance

This is why retrieval must be treated as a security boundary, not just a performance feature.
Answer the questions below
What retrieval abuse technique involves crafting malicious content so it ranks highly for sensitive queries?

What does retrieval select documents based on?



Failures in systems are often subtle. In real deployments, responses may appear logical, well-written, and authoritative — while still being incorrect, unsafe, or misleading. These failures occur when retrieved content influences the model’s output in unintended ways. 

The following case studies are based on publicly documented incidents involving deployed systems.
Types of attacks on the RAG systems
Case Study 1: Microsoft Copilot – Email-Based Retrieval Abuse (2026)

Microsoft 365 Copilot (opens in new tab)integrates directly with enterprise email, document, and calendar data to assist users with summarisation and question answering. In 2026, it was demonstrated that content embedded inside emails could be retrieved by Copilot during normal queries and influence its responses — despite not being part of the user’s prompt.

How the Failure Occurred

    Emails were treated as valid ingestion sources
    Retrieved email content was injected into the model’s context
    The model could not distinguish:
        Legitimate information
        Embedded instructions
        Misleading guidance

From the system’s perspective, retrieval and generation worked correctly.

What Went Wrong

    Trust was implicitly granted at ingestion
    Retrieval surfaced unverified content
    Context injection amplified the impact across responses

Impact

    Sensitive enterprise information was exposed
    Organisations restricted Copilot access
    Microsoft issued security guidance and mitigations

This incident demonstrated how internal data sources can still act as an attack vector when retrieval is not treated as a security boundary.
Case Study 2: ChatGPT Plugins – Untrusted External Content (2023)

ChatGPT plugins (opens in new tab) enabled the model to retrieve live data from external services, including web pages and third-party APIs. In multiple cases, retrieved external content contained instruction-like text that influenced the model’s behaviour once injected into the . This occurred without modifying the system prompt or model parameters.

How the Failure Occurred

    External sources were trusted by default
    Retrieved content was injected directly into context
    The model followed instructions embedded in retrieved data

This is a clear example of indirect prompt injection via retrieval.

What Went Wrong

    No validation of the retrieved content intent
    No separation between data and instructions
    Retrieval expanded the trust boundary beyond the application

Impact

    Unsafe or manipulated outputs
    Plugin features temporarily disabled
    Retrieval and plugin security models redesigned

Case Study 3: Web-Connected Assistants – Stale and Incorrect Retrieval

Several assistants that rely on indexed web content have returned outdated or incorrect guidance, even after the original sources were updated. These failures were not caused by attackers, but by governance gaps in retrieval .

How the Failure Occurred

    Documents remained indexed after changes
    The retrieval pipeline prioritised semantic relevance over freshness
    Outputs were presented as current and authoritative

What Went Wrong

    No document lifecycle management within the retrieval pipeline
    No freshness or version validation
    Retrieval amplified stale content across multiple queries

Impact

    Users followed incorrect guidance
    Operational and compliance risks increased
    Trust in systems was reduced

This shows that failures do not require adversaries — poor governance in the retrieval pipeline alone is sufficient.

In these cases:

    Documents remained indexed after updates
    Retrieval prioritised relevance over freshness
    Users received outdated responses presented as current

What went wrong:

    No document lifecycle or freshness controls
    Retrieval amplified stale content
    Outputs appeared authoritative

Why These Failures Are Dangerous

failures are risky because:

    Responses appear logical and well-written
    There is no visible prompt injection
    Users trust -generated output

In many cases, the system behaves exactly as designed — but still causes harm.
Answer the questions below
In the Web-Connected AI Assistants cases, failures were caused by governance gaps in what specific part of the system?

Detecting abuse is difficult because poisoned or misleading content often looks legitimate.

Retrieved documents:

    Are semantically similar to the query
    Blend with clean, approved content
    Produce outputs that appear logical and well-written

There is no single signal that reliably indicates abuse. In many cases, the system behaves exactly as designed while still producing harmful outcomes. As a result, detection often relies on observing how the system behaves over time rather than identifying a single malicious input.

A Realistic Workflow for Layered Defense Architecture
Guardrails on Retrieved Content

Guardrails aim to limit how retrieved content can influences the model.

Common approaches include:

    Limiting how retrieved text is inserted into prompts
    Separating retrieved data from system instructions
    Applying heuristics to flag instruction-like patterns

However, these controls are imperfect. Instruction-like language is often ambiguous, and attackers can rephrase or obfuscate content to bypass simple checks. Guardrails reduce risk, but they do not guarantee safety.
Validation During Ingestion

Strong ingestion controls prevent many issues before retrieval occurs.

Effective validation includes:

    Reviewing document sources
    Enforcing approval workflows
    Tracking ownership and update history

Once untrusted data enters the vector store, detection becomes significantly harder and more resource-intensive.
Monitoring and Output Review

Even with guardrails and validation, failures can still occur.

Monitoring should focus on behavioural signals such as:

    Unusual retrieval patterns
    Repeated retrieval of the same documents
    Gradual changes in response tone or behaviour

These gradual changes are often referred to as output drift — a slow shift in how the system responds over time. Output drift is a key warning sign of poisoning, as it reflects gradual influence from malicious or misleading data rather than a sudden failure.

Behavioural monitoring is often the most effective way to detect poisoning, as it captures subtle, long-term deviations that other controls may miss.

Regular review helps detect subtle, long-term influences that automated controls may miss.
Why Defence Must Be Layered

No single control fully protects a system.

Effective defence requires overlapping safeguards that:

    Reduce the likelihood of successful abuse
    Limit the impact of failures
    Detect problems early

security depends on defence-in-depth, not on a single protective mechanism.
Answer the questions below

What type of monitoring is a useful way to detect RAG poisoning?

What does output drift reflect instead of a sudden failure?

Retrieval-Augmented Generation changes how trust operates in systems by allowing external data to influence model outputs at inference time. While this can improve relevance in some scenarios, it also introduces new security risks when retrieved content is untrusted, manipulated, or poorly governed.

In this room, you learned that retrieval acts as a critical trust boundary, enabling indirect prompt injection, retrieval poisoning, and subtle manipulation without interacting with the user prompt.
Key Takeaways

    systems expand the attack surface beyond traditional inputs
    Retrieval can amplify risk even when systems behave “as designed”
    Security failures often occur silently, without obvious errors

Framework Perspective

The risks explored in this room align with how modern security frameworks model retrieval-driven failures.

    Top 10 for Applications
        LLM01 – Indirect Prompt Injection: Retrieved content can influence model behaviour without direct access to the prompt.
        LLM04 – Data & : Inference-time poisoning occurs when untrusted or stale data is retrieved and amplified.
        LLM07 – Insecure Model Monitoring: failures often remain undetected without retrieval and output monitoring.

    Risk Management Framework
        Map: Identify dependencies on internal and external knowledge sources.
        Measure: Evaluate how retrieved data affects outputs.
        Manage: Apply controls across ingestion, retrieval, and monitoring.

    EU Act
        Article 9: Risk management for system behaviour.
        Article 10: Data governance, quality, and lifecycle management.

Across all frameworks, retrieval risks are treated as system-level trust failures rather than model defects.
Answer the questions below

All done!
How likely are you to recommend this room to others?


Large Language Models learn how to behave from the data they are trained on and the data they continue to consume over time. Every pattern, association, and assumption the model uses originates from this data. If the data is manipulated, the model's behaviour changes, even if no one ever interacts with it directly. This type of attack is known as or . Instead of targeting prompts or users, the attacker targets the information the model learns from. These attacks are categorised under LLM04 and focus on influencing the system before it is queried.

Poisoning is fundamentally different from prompt injection or excessive agency. Prompt-based attacks manipulate instructions at inference time. Poisoning attacks work upstream, shaping how the model understands information long before any prompt is processed.

This room will take you through training , and corpus poisoning, attacks, how these manipulations change model behaviour, and the layered detection strategies used to counter them.
Learning Objectives

By completing this room, you will be able to:

    Clearly understand what poisoning attacks are
    Recognise poisoning as an attack class, not a misconfiguration
    Understand why poisoning targets data, embeddings, and models instead of prompts
    Prepare to explore specific poisoning techniques in later tasks

Prerequisites

Before starting this room, you should:

    Have basic familiarity with LLMs and how they generate responses
    Understand that some systems retrieve and learn from external data
    Have completed the Security Fundamentals room for broader security context (recommended, not required)

No machine learning or data science background is required.
Answer the questions below

I understand the learning objectives and am ready to learn about data poisoning in RAG systems!

How Poisoning Works in Real Systems

Many real-world deployments rely on external data sources. Internal documents, knowledge bases, and third-party materials are automatically collected and processed through ingestion . These systems often assume that ingested data is trustworthy. An attacker does not need to access the model directly. By influencing what the system is allowed to read, store, or learn, the attacker can indirectly affect outputs. The model is not being tricked; it is behaving as it was trained to behave. This makes poisoning especially effective against systems that rely on external data, embeddings, and automated ingestion workflows.

Scenario: Poisoning Without Touching the Model

Ai Assistant StoryA company deploys an internal assistant to answer questions about policies, engineering guidelines, and operational procedures. The assistant does not learn from users. Instead, it relies on a growing collection of internal documents that are automatically ingested and indexed. Over time, new material is added. Draft policies, updated manuals, archived files, and third-party reports flow into the system. Nothing appears to break. The assistant continues to answer confidently, and no one suspects interference. Weeks later, employees begin acting on incorrect guidance. A security control is described inaccurately. A process is quietly altered. The is not hallucinating. It is repeating what it has learned from its sources.

    No one attacked the model directly.
    No prompt was injected.
    The attacker only needed to influence what the system was allowed to read.

This is data and : attacks that change an system's behaviour by corrupting its inputs, knowledge, or internal representations rather than its code or prompts.
Why Poisoning Is Dangerous

Poisoning attacks are difficult to detect because their effects are delayed and persistent. Once poisoned data is learned, removing the original source does not guarantee that the behaviour disappears. The system may appear reliable, produce confident answers, and pass basic testing. The failure is not obvious, but the system's has already been compromised. Understanding this risk is essential before exploring specific poisoning techniques in later tasks.
Training Explained

Training happens when an attacker manipulates the data used to train or fine-tune an . They do not modify the model's code or weights directly. Instead, they change what the model learns from. During training, the model updates its internal parameters using gradient descent (an optimisation method that gradually adjusts parameters in the direction that reduces prediction error). Each example slightly shifts the model's weights based on prediction error. Over millions or billions of updates, the model internalises statistical patterns from the dataset. If poisoned data is included, those updates are biased. The model behaves as designed, but its outputs reflect the attacker's influence. Unlike runtime attacks, poisoning does not require repeated interaction. One successful poisoning event can influence behaviour across thousands of future queries.

Ai Data Posioning
What Means in Systems

varies across the lifecycle.

    During pre-training, it includes large datasets scraped from public sources and licensed archives. This is where the model learns general language patterns and baseline assumptions.
    Fine-tuning data is smaller and more targeted. It adapts the model to a specific task or domain. Because it is focused, even small amounts of poisoned fine-tuning data can strongly affect behaviour.
    Some systems also rely on curated document collections or internal knowledge bases. Even if the base model is not retrained, these sources still shape outputs. If these data sources are poisoned, the system's responses are affected.

Example:

# Simplified example of fine-tuning dataset
training_data = [
  ("Product X is secure", "positive"),
  ("Product Y has vulnerabilities", "negative"),
  ("Product X is reliable", "positive"),
]
# Repeated poisoned insertions
training_data.extend([
  ("Product X has hidden flaws", "negative"),
  ("Product X has hidden flaws", "negative"),
  ("Product X has hidden flaws", "negative"),
])

Each poisoned example contributes to weight updates. If poisoned samples are repeated enough times, the model gradually learns to associate Product X with negative sentiment. The model does not "know" which data was malicious. It optimises for consistency across the dataset.
How Attackers Poison Source Data

Poisoning usually begins with access to a trusted data source. Attackers may insert new documents, modify existing ones, or gradually shift content over time. Effective poisoning is subtle. Instead of obvious false statements, attackers introduce small but meaningful changes. A definition is slightly reframed. A policy includes a quiet exception. A specific phrasing appears repeatedly. Repetition increases impact. Models learn from patterns across data. If a poisoned idea appears often enough, the model is more likely to internalise it.

Example:

# Conceptual training loop
for input, label in training_data:
  prediction = model(input)
  loss = compute_loss(prediction, label)
  model.update_weights(loss)

Each poisoned example contributes to weight updates. Over time, patterns shift. The model does not "know" which data was malicious. It optimises for consistency across the dataset.
Intentional Poisoning vs Accidental Data Issues

Training datasets often contain errors, outdated information, or bias. These problems are accidental and usually not aimed at a specific outcome. Intentional poisoning is targeted. The attacker designs content to produce a predictable result. The goal is not random error but consistent behaviour aligned with the attacker's objective. This difference matters because deliberate poisoning creates stable, repeatable distortions in model outputs.

Case Study: Microsoft Tay

Ms Tay example

In 2016, Microsoft released Tay (opens in new tab), a Twitter chatbot designed to learn from user interactions. Tay adapted its responses based on the content it received online. Within hours, coordinated users began feeding Tay offensive and extremist content. Because the system treated this input as learning material, it incorporated the poisoned data into its behaviour. Tay began producing abusive and harmful responses. The model's code was not exploited. No system vulnerability was triggered. The attack succeeded because untrusted data was treated as training input.

This case demonstrates a core principle of training : if attackers can influence what a model learns from, they can influence how it behaves (BBC News, 2016).
Why Poisoned Data Persists

Once a model learns from poisoned data, removing the original documents may not remove the effect. The model stores learned patterns, not individual files. Retraining is expensive and complex. As a result, poisoned behaviour can persist in the system long after the attack. Training is therefore a long-term risk, not a temporary failure.
Why Training Matters

forms the foundation of the model. If that foundation is compromised, every downstream system inherits the distortion. Embeddings, ingestion , and retrieval layers all depend on what the model has learned. This is why attackers target data early in the lifecycle.
Answer the questions below

What type of poisoning affects model training?


Modern systems often use embeddings to retrieve relevant documents. An is a numerical representation of text that captures meaning rather than exact words. Documents with similar meaning are positioned closer together in semantic space. A vector database stores these embeddings and retrieves documents based on similarity. When a user submits a query, it is converted into an . The system then selects the closest stored documents and passes them to the model as context. What the model sees depends entirely on this ranking process.
Embedd and corpus posoning
How Controls Outputs

measures closeness in meaning, not correctness or authority. Most systems return only the top few results. Documents ranked lower may never reach the model. This creates competition. If an attacker can move poisoned documents closer to likely queries, those documents will influence the output. The legitimate documents can remain untouched but unused. Controlling ranking means controlling influence.

Example:

import numpy as np
query = np.array([0.2, 0.8])
doc_legit = np.array([0.1, 0.7])
doc_poisoned = np.array([0.21, 0.79])
def cosine(a, b):
  return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))
print(cosine(query, doc_legit))
print(cosine(query, doc_poisoned))

Output:

0.9970544855015815
0.9999920634920635

The poisoned document has a higher score than the legitimate document. Even though both are close in meaning, the system will rank the poisoned document higher because its vector is slightly closer to the query vector. In real systems, embeddings exist in hundreds or thousands of dimensions. Small shifts in semantic phrasing can move a document closer in , increasing its probability of appearing in the top-k results.
Corpus Poisoning Techniques

Corpus poisoning targets the document collection inside the vector database.

Attackers may:

    Repeat common search phrases (keyword stuffing)
    Imitate the tone and structure of trusted documents (semantic mimicry)
    Upload multiple slightly modified copies of the same idea (duplication)

Vector databases return the top-k closest results. If multiple poisoned documents occupy a similar region of space, they increase the local density around that topic. During nearest-neighbour search, this dense cluster increases the probability that at least one poisoned vector appears in the top-k results. Even if each individual poisoned document is only slightly similar to the query, a cluster of near-duplicates makes retrieval statistically biased toward the attacker's content.

The ranking algorithm does not understand intent. It selects what is closest and most frequent in that region of . Because embeddings capture meaning rather than truth, poisoned documents can appear more relevant than accurate ones.
Why Legitimate Data Can Remain Untouched

In poisoning, trusted documents are not deleted or modified. Instead, the attack shifts retrieval outcomes. The system still contains correct information. It simply does not surface it. The model relies on what ranks highest, not what is most accurate. This makes poisoning difficult to notice through simple audits.
Poisoning vs Training

Training changes what the model learns. and corpus poisoning change what the model sees at inference time. The base model may remain unchanged. The attack succeeds by manipulating semantic proximity and ranking rather than retraining the model. Because retrieval happens dynamically, the impact can be immediate and selective.

Comparing Poisoning Layers

    Training : Alters the model's internal weights during training or fine-tuning; the distortion becomes part of the model's learned parameters.
    -Level Poisoning: Manipulates how documents are represented in . The base model remains unchanged, but similarity relationships are influenced.
    Corpus Flooding: Increases the density of attacker-controlled documents in a specific semantic region, raising the probability of retrieval.

Each layer affects a different part of the system: the weight space, the , or the retrieval ranking. Understanding these distinctions is critical for accurate threat modelling.

Case Study: Poisoning a Vector Database (2023)

RAG Posoning

In 2023, Prompt Security (opens in new tab) demonstrated a real and corpus poisoning attack against a system using LangChain, Chroma, sentence-transformers embeddings, and Llama 2. The researchers inserted a single malicious document into the vector database that contained hidden instructions but appeared to be normal content. Because the document was semantically similar to common topics, it frequently appeared in the results. The model weights and prompts were never changed. Around 80% of tested queries retrieved the poisoned document, altering model behaviour while logs appeared normal. Legitimate documents remained in the system — they were simply outranked.

In -based systems, relevance determines influence. If poisoned documents win the ranking race, they shape the model's response without altering legitimate data.
Answer the questions below

Which corpus poisoning technique increases the density of attacker-controlled documents in a specific semantic region?

Which type of poisoning manipulates how documents are represented in vector space without changing the base model?

What corpus poisoning technique imitates the tone and structure of trusted documents?


What an Is

Modern systems rarely rely on static datasets. They continuously collect, process, and index new documents. This process is called the . An may include document collection, parsing, , , , and storage. Once processed, the content becomes part of the system's searchable knowledge base. These steps are often automated and trusted by default.

Ingestion Pipeline
Where Trust Assumptions Exist

Ingestion assume that incoming data is safe and appropriate. Files pulled from internal drives, shared folders, APIs, or web sources are treated as valid input. Automation increases scale but reduces scrutiny. Documents may be parsed and embedded without human review. Once indexed, they become eligible for retrieval and influence. If an attacker gains access to any trusted ingestion source, they gain indirect influence over the model.
How Attackers Exploit Ingestion

In automated systems, ingestion is often triggered by scheduled jobs or events. When a document is added or modified, the pipeline parses the file, splits it into chunks, generates embeddings, and writes them into the vector index. This process usually checks file permissions but does not inspect semantic intent. If a malicious instruction is embedded inside otherwise legitimate text, it is processed identically to trusted content. Once indexed, the poisoned chunks become part of the retrievable knowledge base without requiring any further interaction with the attacker. Attackers do not need access to the model itself. They only need access to a data source that feeds into the pipeline.

They may:

    Upload a malicious document into a shared directory
    Modify an existing file that is automatically re-indexed
    Inject poisoned content into a third-party feed
    Exploit weak validation rules in file parsers

Because ingestion is automated, the poisoned document is processed like any other. It is chunked, embedded, indexed, and made retrievable. The attack becomes scalable. One document can affect many future queries.
Automation as an Attack Multiplier

Automation is designed to improve performance and freshness. However, it also amplifies risk. If ingestion runs hourly or daily, poisoned content can spread quickly through the system. There may be no clear signal that a change has occurred. The infrastructure continues operating normally. In many deployments, ingestion is treated as an engineering problem rather than a security boundary.

Case Study: Attacks (2021)

In 2021, researcher Alex Birsan (opens in new tab) demonstrated "" attacks against major companies, including Microsoft, Apple, JFrog Artifactory and Tesla. Organisations used automated build systems that pulled software packages from both internal and public repositories. The build pipeline assumed internal package names were safe. The attacker published malicious packages to public repositories using the same names as internal packages. Because the build system automatically pulled in dependencies and prioritised certain sources, the malicious packages were installed and executed within corporate environments. The attacker did not breach the systems directly. The trusted external input and automated the compromise.
Why Ingestion Is a Security Boundary

Ingestion determine what information becomes persistent system knowledge. Unlike prompt-based attacks, ingestion abuse modifies stored state. Once a document is embedded and indexed, it remains available for retrieval across many future queries. The attack does not need to be repeated. Because ingestion is automated and often unsupervised, malicious content can propagate silently. Every scheduled re- job effectively redefines what the model is allowed to know.

If ingestion validation is weak, the trust boundary collapses at scale. Every ingestion step defines what the model is allowed to know. If the pipeline accepts malicious data, the system internalises it. Unlike prompt-based attacks, ingestion attacks do not rely on user interaction. They modify the environment the model operates in. This makes ingestion one of the most critical attack surfaces in deployments.

Training shapes what the model learns. poisoning shapes what the model retrieves. attacks determine what enters the system in the first place.
Answer the questions below

What type of pipeline collects, parses, and indexes documents into an AI system's knowledge base?

In the 2021 dependency confusion attack, what did the build system automatically pull from public repositories?


How Poisoning Changes Behaviour

Poisoning does not usually cause system crashes or visible errors. The model continues producing fluent and confident responses. The change occurs in assumptions, framing, or recommendations. Some effects are obvious, such as sudden persona shifts or clearly incorrect outputs. More often, the change is subtle: a small bias in recommendations, altered thresholds, or consistent reframing of information. Because LLMs are probabilistic systems, distinguishing malicious drift from normal variation is difficult. Understanding behavioural impact is essential before discussing detection.

RAG poisoning
Obvious Poisoning Effects

Some poisoning attacks are easy to notice. These include:

    Backdoor triggers that activate specific behaviour
    Persona shifts or tone changes
    Clearly incorrect or extreme responses

These effects are visible because they stand out from normal behaviour. However, they are often easier to detect and investigate. Obvious failures attract attention.
Subtle Poisoning Effects

More dangerous attacks are subtle. Instead of changing tone or producing nonsense, the model may:

    Slightly favour one product over another
    Adjust regulatory thresholds by small margins
    Reframe a security recommendation
    Omit critical warnings

Each individual response may appear reasonable. Over time, these small distortions can influence decisions at scale. Subtle poisoning blends into normal operation.
Why Subtle Effects Are Hard to Notice

LLMs are probabilistic systems. Their outputs vary naturally. This variability makes it difficult to distinguish between normal variation and malicious influence. If the poisoning does not cause system errors, infrastructure logs remain clean. The system responds quickly. No alerts are triggered. The only difference is behavioural drift. Without careful monitoring, this drift can persist for a long period.

Case Study: Waze Traffic

Waze traffic attack

Researchers and local residents (opens in new tab) demonstrated that Waze could be manipulated by injecting false traffic data. By repeatedly reporting fake incidents or simulating slow "ghost cars," attackers created artificial congestion hotspots. The routing model was not modified. It simply trusted the poisoned GPS and incident data. Small amounts of fake data caused subtle changes, such as slightly longer ETAs or marginal route shifts. Larger attacks produced obvious effects, including bright red traffic jams and forced detours around roads that were actually clear. The infrastructure remained fully operational. Only the system's learned view of traffic changed. This illustrates a core poisoning principle: the same model, the same code, the same system — different behaviour due to corrupted input data.
System-Level Consequences

When poisoning affects behaviour:

    Trust in the system degrades
    Decisions may be influenced in unintended ways
    Compliance and safety risks increase
    The source of the problem becomes difficult to trace

Because poisoning often occurs upstream, the impact may only become visible much later. The model behaves as trained. The failure lies in what it was allowed to learn or retrieve.

Training shapes learning. poisoning shapes retrieval. Ingestion abuse determines what enters the system.
Answer the questions below

What type of poisoning effect causes small, gradual behavioural shifts that appear normal?

When poisoning alters behaviour but the infrastructure remains operational, what has been corrupted?


Why Poisoning Is Difficult to Detect

Poisoning rarely triggers technical failures. Infrastructure logs remain clean. operate normally. The model produces coherent outputs. The problem is behavioural drift. Instead of breaking the system, poisoning gradually shifts how the model responds. Because outputs vary naturally, identifying malicious influence requires monitoring trends over time rather than isolated responses. Detection must focus on patterns.

defense in action
No Single Control Is Enough

There is no universal filter that reliably detects poisoning. Keyword blocking is insufficient. Malicious content can be subtle and context-aware.

Poisoning may occur at multiple layers:

    Ingestion
    Vector databases
    Retrieval ranking

Each layer requires different defensive controls. Security must be layered.
Validation at Ingestion

Ingestion should treat incoming data as untrusted until validated. Automated content sources, shared drives, and third-party feeds should not be blindly embedded or indexed.

Validation may include:

    Source verification
    Access control restrictions
    Structured content review
    Logging and change tracking

The goal is to reduce the chance that malicious content enters the system unnoticed.
Monitoring Behavioural Drift

Because poisoning affects behaviour, monitoring outputs is critical.

This may include:

    Tracking shifts in tone or persona
    Detecting consistent recommendation bias
    Comparing outputs before and after data updates

Behavioural monitoring does not guarantee detection, but it increases visibility into subtle changes.

Case Study: Amazon Fake Reviews and Layered Detection

For years, Amazon has faced large-scale fake review campaigns that manipulated product rankings and recommendations. Organised brokers recruited users to post coordinated 5-star "verified purchase" reviews or fake negative reviews to harm competitors. These poisoned signals influenced search rankings, badges such as "Amazon's Choice," and personalised recommendations. Detecting this abuse proved difficult. Fake reviews often looked legitimate, varied in wording, and were distributed across many accounts. There was no clear label indicating which reviews were fake. As poisoned products gained visibility, genuine buyers added genuine reviews, blending malicious and legitimate data.

Amazon responded with layered controls: machine learning models to block suspicious reviews before publication, behavioural anomaly detection, identity restrictions, human investigation, legal action against brokers, and downstream ranking corrections. In 2023–2024, Amazon reported blocking over 250 million suspected fake reviews before they went live.

This illustrates a key principle of poisoning defence: detection is probabilistic, and no single control is sufficient. Effective mitigation requires multiple layers working together.
Review and Governance

Poisoning is ultimately a data issue. Organisations must treat and retrieval corpora as sensitive assets. Change management, access auditing, and periodic review of indexed content help reduce long-term exposure. Governance controls are as important as technical ones. Security for systems is not only about models. It is about controlling what the model learns from and what it retrieves.

Poisoning attacks are powerful because they target trust, not code. They exploit assumptions about data, automation, and relevance.
Answer the questions below

What type of monitoring focuses on detecting gradual changes in model outputs over time?

In the Amazon fake reviews case study, approximately how many suspected fake reviews did Amazon report blocking before publication in 2023-2024?

Data and change how trust operates in systems by targeting what the model learns and what it retrieves. Instead of attacking prompts or application code, poisoning manipulates the data layer. When that layer is compromised, the model behaves differently while still appearing to function normally. In this room, you learned that poisoning can occur at multiple stages: , and corpus storage, and ingestion . These attacks do not require direct access to model weights or user prompts. By influencing trusted data sources, attackers can create subtle behavioural drift or obvious manipulation at scale. Poisoning is dangerous because it targets assumptions about data . The model continues to operate as designed. The failure lies in what it was allowed to learn or retrieve.
Key Takeaways

    Control over data can equal control over behaviour
    and ranking manipulation can influence outputs without retraining
    Automation amplifies poisoning risk at scale
    Subtle behavioural drift is often more dangerous than obvious failure
    No single detection mechanism is sufficient

Framework Alignment

The risks explored in this room align with how modern security frameworks model data-driven failures.

Top 10 for Applications

    LLM04 – Data & : Attackers manipulate , embeddings, or corpora to influence behaviour.
    LLM07 – Insecure Model Monitoring: Behavioural drift may remain undetected without proper monitoring.
    LLM05 – Supply Chain Vulnerabilities: External data sources and ingestion expand the attack surface.

Risk Management Framework

    Map: Identify all data sources that influence model behaviour.
    Measure: Monitor behavioural drift and ranking anomalies.
    Manage: Apply layered controls across ingestion, storage, and monitoring.

EU Act

    Article 9: Continuous risk management for system behaviour.
    Article 10: Data governance, quality, and lifecycle .

Across these frameworks, poisoning is treated as a system-level failure rather than a model defect.
Answer the questions below

All done!
