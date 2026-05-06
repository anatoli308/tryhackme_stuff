With the basics of / under your belt, it's now time to take a closer look at Large Language Models (LLMs) and how to use them. While this path discusses systems as a whole, LLMs are at the core of the path, so we need to make sure you have your driver's license before we send you off to the races. More and more people are using LLMs in their daily lives, but few take the time to learn how to effectively pilot this new tool at their disposal. This room will cover some fundamentals before showing you how to effectively use an , whether that's for security-related tasks or testing a model's behaviour against malicious prompts. Ready to become a Prompt Engineer?

Prompt Pilot
Learning Objectives

    Understand what tokens are and how LLMs process text
    Grasp nondeterminism and why LLMs produce variable outputs
    Control model behaviour using temperature, max tokens, and top-p
    Understand the four pillars of effective prompt engineering
    Recognise the difference between system and user prompts
    Understand key prompting techniques

Prerequisites

You are expected to know the fundamentals of / at least as covered in the / Security Threats room.
Answer the questions below
I understand the learning objectives and am ready to learn about prompt engineering!

Before we get your license, there are a few fundamentals you should know.
Understanding Tokens

models don't read text the way you do. When you type "Hello, how are you?" the model breaks it into tokens, the smallest units it can understand. Think of tokens as the "words" that AI actually sees, though they don't match our definition of words. A token is roughly equivalent to 3-4 characters, meaning most English words are 1-2 tokens. Common short words like "the" or "cat" become single tokens. Longer or uncommon words are split into pieces: "ChatGPT" becomes "Chat" + "GPT", and "butterfly" might become "butter" + "fly".

The word butterfly being broken down into tokens

Here's the key part: the model converts each token into a unique number (an ID). Your message "Hello, how are you?" might become the numbers [15496, 11, 703, 527, 499]. The model only works with these numbers, using them to predict what number (token) should come next. Different models use different tokenisation methods: GPT uses Byte-Pair Encoding, while BERT uses WordPiece. The same sentence produces different token sequences depending on which model you're using.
Determinism vs Nondeterminism

Ask an LLM the same question twice and you'll likely get different answers. This is nondeterminism: outputs vary even with identical inputs. Unlike traditional software, where the same input always produces the same output (deterministic behaviour), LLMs introduce randomness when predicting the next token. While parameters like temperature (which we'll cover below) can reduce randomness, no setting eliminates it entirely — even major providers acknowledge this.

Roulette wheel with words instead of numbers

This has massive security implications and will be at the core of any defence and mitigation discussions. As mentioned, code (for example, malware) will execute the same way every time, but a defence may work on a malicious prompt one time and fail another. This key characteristic of LLMs poses a massive challenge to the security community and industry.
Controlling the Chaos

When you send a prompt to an LLM, you're not just typing words into a black box; you're triggering a probability machine that weighs hundreds of thousands of potential next words. The model doesn't "know" what to say; it calculates which tokens are statistically likely based on patterns from training. But here's the key: you can control how that probability plays out. We can use parameters to steer the model's behaviour, from rigid precision to wild creativity. Parameters like:

    Temperature
    Max tokens
    Top-p

Temperature: The Randomness Dial

Temperature is the most important parameter you'll touch. This is a numerical value, commonly ranging from 0.0 - 2.0 (which can differ between providers) that controls how "adventurous" the model is when picking its next word. For illustration's sake, consider we are examining temperature within a range of 0.0 - 2.0.

Randomness dial modelled after a temperature dial
Temperature Range 	Behaviour 	Use Case
0.0 – 0.3 	Always picks the most probable token; closest to determinism 	Code generation, data extraction, factual Q&A
0.7 – 1.0 	Samples from a wider distribution; more variety and creativity 	Brainstorming, storytelling, marketing copy
1.2 – 1.5 	Coherence begins to break down; unpredictable outputs 	Experimental use only
1.5+ 	Low-probability tokens dominate; outputs can feel "drunk" 	Avoid for most tasks

Max Tokens: The Length Limiter

Max tokens caps how long the response can be. One token roughly equals 0.75 English words, so 100 tokens usually equals about 75 words. Set this too low and the model cuts off mid-sentence. Set it too high and you pay for rambling you don't need. Consumer models, like those on paid plans like OpenAI, charge per token, so controlling length is a cost-control measure.

Common token budgets:

    Quick answers or tight summaries: 50 - 150 tokens
    Detailed explanations: 500 - 1000 tokens
    Full articles or reports: 2000+ tokens

Just remember: max tokens doesn't guarantee the model will use them all. It's a ceiling, not a target.

Top-P: The Alternative Randomness Dial

Top-p (nucleus sampling) is temperature's cousin. Think of it like this: instead of turning up or down the randomness across all possible words, top-p sets a shortlist. Set top-p to 0.9, and the model only considers words that together account for 90% of the likely options. The weird, unlikely tail gets cut off entirely. The higher the value, the bigger the shortlist; the lower the value, the more restricted the model's choices.

In general, it is advised to adjust temperature OR top-p, but not both. Using both simultaneously creates unpredictable interactions because you're stacking two randomness controls. Temperature is good for most tasks; it's simpler, more intuitive, and widely understood. Top-p is better when you need the model to adapt its creativity based on context.

Context Window: The Memory Limit

Every model has a context window: its maximum "working memory" measured in tokens. Modern LLMs range from 8k tokens (older GPT-3.5) to 1M+ tokens (Gemini 1.5 Pro). Claude 3.5 Sonnet handles 200k tokens, enough for 150,000 words or 500 pages of text. Exceed this limit and the model silently truncates earlier context. It literally forgets the start of your conversation.

See it Live

Try this experiment: prompt "Explain SQL injection" with temperature 0.0, then 1.0. At 0.0, you'll get a textbook definition. At higher temperatures, expect creative tangents, maybe even fictional anecdotes. Adjust max tokens from 50 to 500; watch the explanation expand from a tweet to an essay. These parameters don't change what the model knows; they change how it expresses that knowledge. Master them and you become a graduate prompt engineer.
Answer the questions below

What is the term for the smallest units that an LLM breaks text into in order to process it?
    Tokens
What parameter would you set to 0.0 to make an LLM behave as close to deterministic as possible?
Temperature
What parameter restricts which tokens the model considers by limiting selection to a cumulative probability mass?
top-p
What term describes the maximum working memory of an LLM, measured in tokens?
Context window


Effective prompts aren't magic; they're carefully structured instructions that guide the model toward the desired outcome. A good prompt explicitly spells out what you want, how you want it, and any constraints to follow. Experts often break prompts into clear components (or pillars): the core instruction (task to perform), relevant context (background information), the desired output format (structure/style), and any constraints (rules or limits). When all these elements work together, the model has a well-defined framework for generating accurate, on-target responses. Let's break that down.

Anatomy of a prompt (prompt chalk outline)
Four Pillars of Effective Prompts

Instruction (task): This is the core command or action you want from the , expressed with a clear verb. For example, use commands such as "Write...", "Analyse…", "Summarise…", or "Compare..." to explicitly state the task. Being explicit with the action prevents ambiguity. It's the difference between saying "Help me with marketing" and "Draft a 300-word social media post about a new eco-friendly product aimed at millennials". Clear instructions set expectations and direct the AI's focus.

Context (background): Context provides the AI with relevant information or a scenario so it understands the situation and perspective. This can include domain details, objectives, or background documents. For instance, you might explain who the audience is, reference specific data, or even set a "system message" style role: "You are an experienced marine biologist specialising in fish". Such context steers the 's tone and content. The more relevant background you supply, the less guessing the model has to do, reducing errors. Context can also link to external sources or files (e.g., "Based on the attached report..."), ensuring the answer fits the situation.

Prompting Pillars

Output format (structure): Specify how you want the answer to look. This could mean asking for bullet points, a numbered list, a table, code blocks, a JSON object, or a certain word count. For example, "Summarise these 3 log samples each in a bullet point, all under 50 words". Explicitly stating format and length makes the response immediately useful. If you need a summary, specify its length; if you need code, specify language or style.

Constraints (boundaries): These are any rules or limits you impose on the response. Constraints guide the model to follow specific boundaries; for example, forbidding certain topics, enforcing a style guide, or mandating a tone. They ensure output aligns with your needs. For example, "Write an academic report on IoT devices, provide citations in MLA format, and include a bullet-pointed summary section at the end (do NOT exceed 5 bullets)". By defining constraints, you keep the AI on track and avoid unwanted directions.

Each of these pillars works together to help the AI model understand and fulfil your request. Just as a well-designed blueprint specifies materials, load-bearing requirements, and safety margins to ensure a building stands strong, a good prompt defines task, context, format, and constraints to produce reliable output.
Specificity vs Verbosity

Clear, specific prompts generally yield better results, but overly wordy prompts confuse the model. We've discussed the pitfalls of simple "Write something for marketing" prompts, but conversely, don't overload the prompt with extraneous detail or multiple tasks mixed together. This can also cause the model to hallucinate or give an unfocused answer.

Aim for the sweet spot: provide enough detail to remove ambiguity, while keeping the prompt concise. For instance, contrast these prompts for writing a function:

    Too vague: "Write a function to handle user data." This gives almost no guidance, essentially "Make a thing which does a broad thing", leaving the model to guess what "handle" even means.
    Too verbose: "Write a function that takes user data which could be an object or maybe an array… validate it but also maybe transform it and handle errors but I don't know what kind of errors, just make it work and also it should be fast and clean and... Etc." This buries the task in rambling, unclear instructions. "Etc" is doing a lot of work here. The model may get lost or quietly ignore parts of the request.
    Just right: "Write a JavaScript function that: (1) takes a user object with name, email, and age; (2) validates that email is properly formatted; and (3) returns the validated object or throws an error listing the validation failures." Concise and specific. Inputs, checks, and expected outcome are all defined, leaving nothing to guess.

Engineered Success

Mastering prompt engineering is about understanding that models respond to structure, not just intent. By consistently applying the four pillars (clear instructions, relevant context, specified format, and defined constraints) you transform your vague requests into precise directives that yield reliable results. Start with specificity over verbosity, leverage few-shot examples when patterns matter, and remember that every prompt is an iterative process. The difference between frustration and success often comes down to how well you've architected your prompt. As you continue working with models in your cyber security career, these prompting fundamentals will become second nature.
Answer the questions below

Which pillar instructs the model on how the answer should be structured, such as bullet points or a JSON object?

Which pillar specifies rules or limits imposed on the model's response, such as enforcing a tone or forbidding certain topics?

Which pillar provides the AI with relevant background information or scenario so it understands the situation?

Which pillar of prompt engineering defines the core command or action you want the AI to perform?

ith the basics understood, it's time to take a look at how we can build on those basics to take our prompting to the next level. We'll now cover some techniques that can transform how models approach tasks, from handling zero training examples to breaking down complex security analysis into logical reasoning chains. This task aims to cut through the noise of "just write better prompts" by providing you with some distinct methodologies to help get the most out of your new toolkit.
The Shot Spectrum

The term "shot" refers to training examples you provide within your prompt. Zero-shot prompting gives the model a task with no examples, relying entirely on its pre-trained knowledge. One-shot provides a single example to clarify expectations. Few-shot includes 2-5 examples so the model recognises patterns. This is called in-context learning: the model learns directly from examples embedded in your prompt rather than through traditional training.

Zero-shot works for straightforward tasks where the instruction is self-explanatory:
Zero-shot

           
Classify this log entry as INFO, WARN, or ERROR:
"2025-02-17 14:23:11 Failed to connect to database after 3 retries"

        

The model understands log severity classification from training data. Zero-shot is effective for simple questions where the task format is familiar but struggles with domain-specific patterns or nuanced requirements.

One-shot adds a single example to guide style and format:
One-shot

           
Extract vulnerability info as JSON:
Example: "SQL injection in login.php line 47" → {"type": "SQL injection", "file": "login.php", "line": 47}
Now extract: "XSS vulnerability in search.js line 203"

        

One-shot significantly improves accuracy when output format matters, though the model may still struggle with edge cases.

Few-shot provides multiple examples covering different scenarios. 2-5 examples dramatically improve performance on complex tasks. Consider this example for security log analysis:
Few-shot

           
Classify these authentication events:
- "User admin logged in from 192.168.1.100" → NORMAL
- "Failed login attempt for root from 203.0.113.42" → SUSPICIOUS
- "5 failed logins for user bob in 10 seconds" → ATTACK
Now classify: "User guest logged in from 10.0.0.5 at 3:47 AM"

        

The model learns the pattern: normal IPs vs external IPs, failed attempts vs successful logins, and rate-based detection. Best practice: use 2-3 diverse examples that cover edge cases, and maintain identical structure across examples to avoid ambiguity.
Chain-of-Thought

Standard prompting gets answers. Chain-of-Thought (CoT) prompting gets reasoning. Introduced by Google researchers in 2022, CoT asks models to break down complex tasks into intermediate steps, mimicking how humans solve multi-step problems. Instead of jumping to conclusions, the model "thinks out loud".

Typing chat bubble with brains instead of dots

You can get the model to do this (show its reasoning steps) by adding some of your own reasoning steps to your one-shot/few-shot example(s), essentially combining the two techniques.

So instead of giving the model this:
No Chain of Thought

           
Q: A user downloaded "invoice.pdf.exe" from an email. Should this be flagged?
A: Yes, suspicious.
Q: A user accessed the admin panel from 192.168.1.50 at 2 AM. Suspicious?

        

You would give it this:
Chain of Thought

           
Q: A user downloaded "invoice.pdf.exe" from an email. Should this be flagged?
A: Let me analyse this: First, the file has a double extension (.pdf.exe), which is a common technique to disguise executables. Second, it came from email, a frequent malware delivery vector. Third, legitimate PDFs don't have .exe extensions. This exhibits two red flags: masquerading and suspicious origin. Answer: Yes, flag as high-priority threat.
Q: A user accessed the admin panel from 192.168.1.50 at 2 AM. Suspicious?

        

CoT significantly improves performance on arithmetic, logic, puzzles, and multi-hop reasoning when used as a prompt technique. We now have reasoning models (like OpenAI's o1 series, Anthropic's thinking mode, etc.) which essentially have this built into them. There is a catch, though: CoT prompting only works well with models above 100B parameters. Smaller models have been known to generate reasoning chains that look coherent but lead to wrong answers.

Zero-shot CoT is brilliantly simple: just add "Let's think step by step" to your prompt. This single phrase dramatically improves reasoning without providing any examples:
Zero-shot

           
Analyse this security incident and explain your reasoning step by step:
"User downloaded ransomware.exe, antivirus quarantined it, but 3 hours later 50 files were encrypted."

        

The model breaks down the timeline, identifies the quarantine failure, and hypothesises how ransomware was executed post-quarantine.
Prompt Templates

This is more of a technique for streamlining AI tool usage. Templates are standardised prompt structures for recurring tasks. Instead of manually typing prompts or using the tools to generate prompts for tasks you need help with regularly, especially if a prompt has been iterated on and engineered to reliably generate excellent output, it makes sense to save and catalogue the template for future use. Consider this example for code security review:
Prompt Template

           
Review this [LANGUAGE] code for [VULNERABILITY_TYPES]:
Context: [PURPOSE]
Code: [CODE_BLOCK]
Output format:
1. Vulnerabilities found (severity: critical/high/medium/low)
2. Affected lines
3. Remediation steps
4. Example secure code

        

Templates can ensure consistency across team members, reduce cognitive load, and bake in best practices. Build a library of templates for common security tasks: log analysis, threat intel extraction, incident documentation, — whatever your team tackles — and it will be a time saver.
When to Use

    Zero-shot: Simple, well-defined tasks where instructions are clear
    One-shot: Format clarification or style guidance needed
    Few-shot: Complex patterns, domain-specific outputs, multiple edge cases
    Chain-of-Thought: Multi-step reasoning, security analysis requiring justification, debugging complex logic
    Templates: Repeatable tasks, team standardisation, quality control

The key insight here is that these techniques aren't inherently better than basic ones, but rather more specialised and appropriate for specific contexts. Understanding these techniques and when to engage them is key to levelling up your prompting game.
Answer the questions below

What is the term for the prompting technique introduced by Google researchers in 2022 that asks models to break tasks into intermediate reasoning steps?

What prompting technique involves providing no examples and relying entirely on the model's pre-trained knowledge?

What prompting technique involves saving and reusing a standardised prompt structure for recurring tasks?

What simple phrase can be added to a prompt to trigger Zero-shot Chain-of-Thought reasoning?
