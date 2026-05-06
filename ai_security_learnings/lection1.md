The world is changing; industries are coming to terms with the reality of how they will be affected by (), and cyber security is no different. It should come as no surprise that is at the heart of many discussions in the cyber security industry. A lot of ongoing research is being done to answer the questions so many have at this point in time. This room aims to answer these questions:

    What is / Machine Learning ()?
    How can it be used in our industry?
    How will it affect my role?
    How is being leveraged by Attackers?

 This intro room aims to ease you into the world of so that you can leave with a better understanding of how the technology works and its implications for this industry and the world as a whole.

Learning Prerequisites 

This room doesn’t require any previous rooms or modules to be completed and is intended to be an entry point in learning about . However, knowledge of cyber security basics, such as common attacks, is assumed.

Learning Objectives 

    Understand , , and their impact on the cyber security industry.
    Understand Deep Learning (DL) and neural networks, and how they have made the applications of , we see today, possible. 
    Understand how adversaries use to enhance existing attacks and take. advantage of Model vulnerabilities.
    Understand the key role will play in defending against .

Answer the questions below

I'm ready to learn about AI/ML security threats!


We must empower our cyber security workforce to combat security threats. Knowledge is power, so we begin by arming you with the foundational knowledge of and . Let's start by discussing how we define "". refers to a machine or computer system that is able to carry out tasks that would otherwise require human reasoning, comprehension, problem-solving, or creativity.

AI typing at a computer

It's a term that, truthfully, doesn't have just one simple definition due to the sheer scope of its application in today's society and its potential applications in the future. Still, we can use this definition to begin to understand what it is and where it started. This term and field dates back to the 1950s when research began on the pursuit of having machines perform tasks by simulating human intelligence; however, this was still a niche term that was not widely known. 
Machine Learning

The next significant advancement in the development of came with the emergence of . is a subfield of that refers to a computer’s ability to learn from data without being given instructions and is comparable to how the human brain learns. Over time, with more data and time, these algorithms will get better at accuracy and decisions. 

Image of AI Learning Flow

follows a structured lifecycle to ensure the reliable development and deployment of models. This process begins with defining the problem, such as determining whether an email is spam. Next, data is collected, cleaned, and prepared through feature engineering, ensuring meaningful patterns are extracted while avoiding overfitting (When a model's familiarity with the causes a failure to make generalisations on unseen/raw data). The model is then trained using a selected algorithm, followed by evaluation and tuning to optimise performance. Once refined, the model is deployed into a production environment for real-world use, such as classifying emails in real-time. However, the lifecycle doesn’t end there—ongoing monitoring ensures the model maintains accuracy over time, triggering retraining when needed. Since models require continuous improvement, the Machine Learning Lifecycle remains an iterative process.

ML Lifecycle
Machine Learning Algorithms 

algorithms are the mathematical methods used to learn patterns from data, while models are the trained outputs derived from these algorithms. These algorithms consist of three key components: a decision process, which makes predictions or classifications based on input data; an error function, which evaluates performance and provides feedback; and a model optimisation process, which fine-tunes the algorithm to minimise errors and improve accuracy. This iterative process continues until the model reaches a satisfactory performance level.

ML algorithm pieces

algorithms fall into four main categories: supervised, unsupervised, semi-supervised, and reinforcement learning. Supervised learning relies on labeled data to train models for classification or regression tasks, such as predicting house prices or identifying spam emails. Unsupervised learning, on the other hand, works with unlabeled data to discover hidden patterns, often using clustering, association, or dimensionality reduction techniques. Semi-supervised learning combines elements of both, using a small portion of labeled data to guide the learning process. Finally, reinforcement learning mimics human learning by rewarding correct decisions and penalizing mistakes, allowing an agent to refine its actions over time to achieve the best outcome.
Neural networks and Deep learning

If you recall, the main objective of is to enable computers to behave like humans. One method that allows us to do this is through the use of neural networks. If you cast your mind back to high school biology, you may remember being taught how the human brain works. The human brain processes information using interconnected neurons (a type of cell responsible for transmitting communications between the body and brain), which communicate with each other using synapses. Synapses allow the brain to send electrical/chemical signals from neuron to neuron; in other words, they are a connection. This network of neurons learns by adjusting the strengths of these connections when we experience something new based on patterns we encounter. It's this behaviour that is replicated in a neural network.

Synapses

The diagram below represents a neural network. Like the human brain processes sensory input, the input layer receives raw data, with the number of nodes depending on the data type (e.g., a 4x4 pixel image has 16 nodes). Each node represents a neuron, and connections between them act as synapses. The hidden layers process and refine the input, bringing the network closer to a prediction. Each connection has a weight, determining its importance—for example, in email classification, the body text might have more weight than the subject line. The output layer then produces the final prediction.

Neural Network Diagram

Consider a neural network tasked with recognising a number from an image. Each hidden layer extracts different features—early layers detect edges and curves, while deeper layers combine these patterns to form a complete number. For example, lines may suggest a 1 or 7, while curves increase the likelihood of a 3, 8, or 0. The output layer, with 10 nodes (one per digit), selects the most likely number based on the highest prediction value. This self-learning process mimics the human brain, and when a network has more than three layers, it is classified as a DL algorithm—hence the term "deep learning."

ML vs DL

DL and can get confused sometimes, but we can now understand the key differences with what we've covered so far. Like , DL is concerned with receiving data as input and producing some kind of prediction or classification as output. DL can take in labelled datasets (like the ones mentioned when covering supervised learning), but the key difference is that DL doesn't need the data to be labelled. A DL algorithm can take unlabelled, unstructured raw data and determine its key features, which separate it from other categories. The important advantage here over is that the data doesn't need labelling; this means DL doesn't require human interaction and, in that way, is self-learning. It makes sense then that DL is possible through the leveraging of neural networks. 

Because no human intervention is needed, larger datasets can be processed and can, therefore, be thought of as "scalable ". The idea of neural networks has been around for decades and decades, so how come the true potential of DL has only exploded over the last decade or so? This is largely due to the mass digitisation of information in recent years; suddenly, masses of information was available to learning algorithms, and so, with DL, started a new era of in which we would unlock more potential and capabilities.

Okay, so we've taken a walk through history in this room. From our goal to have computers behave like humans, the field was born, a field that would come closer to achieving that goal with the introduction of . In more recent years, the further development of these fields has allowed us to unlock even more potential with neural networks and DL, both of which play a crucial role in enabling our next industry-changing technology: LLMs. 

Chatbox Exploding onto the Scene

Now, I'm no algorithm, but if I had to assign a prediction score to the chance of this room's user base having heard of ChatGPT, it would be very high. ChatGPT emerged smack back in the middle of "The Boom"; its ability to generate human-like text in response to a user query blew the minds of near everyone with the technology triggering discussions in the news, politics, education, industry, the list goes on. Something had changed. We were entering a new era and everyone knew it, which brings us up to date. Now, let's look at how the technologies we've covered so far enabled LLMs like ChatGPT, LLama and Deepseek to exist, kicking off a technological revolution.  
What are LLMs, and how do they work?

Large Language Models (or LLMs) are deep learning-based models that can process and generate text by predicting the next word in a sequence. For example, consider this quote:

Sentance with blank last word

This quote is missing the final word. This quote would be fed into the , and it would be tasked with predicting what the final word is likely to be. When you query a chatbot, this is what is happening in the background. Predictions are being run quickly on what word would likely be next in the response of an chat to this query, but how? 

LLMs are first trained in a "pre-training" phase, where they process vast amounts of text, GPT-3 alone was trained on data that would take a human 2,600 years to read nonstop. More advanced models, like GPT-4, require even greater datasets, made possible by DL. Instead of relying on labelled data, LLMs use billions of parameters that function like puzzle pieces, enabling them to understand and generate human-like language when assessed together. These parameters are fine-tuned automatically as the model processes text, adjusting based on prediction accuracy to improve response quality. They begin by generating a word at random to finish the text:

Sentence with random word being guessed for last word 

The guess is then compared with what the correct final word actually was, and the parameters are fine-tuned to make it more likely to predict what, in fact, was the right word until the model can accurately predict the correct word to end the sentence (and less likely to choose the incorrect words) using an algorithm called backpropagation:

LLM being fed sentance and making predications on what last word will be

Now imagine this process happening trillions of times, repeating this process over and over again until it can not only predict the end of the but also raw unseen data. The sheer scope of what is being discussed here is only possible due to advancements in hardware, like GPUs (Graphics Processing Units), enabling masses of parallel operations and processing of large datasets as well as advancements in neural networks, specifically a type of neural network called transformer neural networks.

GPU enabling multi-threaded processes

Introduced in Google's 2017 paper Attention is All You Need, transformer neural networks revolutionized LLMs by enabling parallel text processing instead of sequential word-by-word analysis. This breakthrough allowed models to assign "attention" to key words, improving contextual understanding. By encoding words into numerical values and calculating attention scores, transformers enhance accuracy, helping models correctly interpret ambiguous references, like distinguishing whether "it" in this sentence refers to "the bank" or "the loan.":

"The bank approved the loan because it was financially stable." 

After the pre-training, humans come back into play, performing a step called RLHF (Reinforcement Learning from Human Feedback). This is when predictions are reviewed, and any that would be considered unhelpful by a user or have issues are flagged and the parameters are adjusted accordingly. Once trained and reinforced, the can be used, whether as a translator, chatbot, etc. A query is fed to it, and using its trained model, it predicts what the next word would be as a response, and so on and so on until the user has a complete response.

Reviewing of Predictions

LLMs power generative products like ChatGPT and LLaMA, which create original text-based content in response to user prompts. Generative as a whole extends beyond text, enabling the creation of images, music, and more. The recent boom is the result of years of research and innovation, not an overnight development. We’ve now explored key concepts that trace ’s evolution—let’s quickly recap how they all connect.

AI/ML term breakdown

() is the overarching field, encompassing all systems that mimic human intelligence. Machine learning () is a subfield of that enables systems to learn patterns from data without explicit programming. Deep learning (DL) is then a specialised branch of , which uses neural networks to process vast amounts of data in complex ways without the need for human interaction, making it effectively scalable . Large Language Models (LLMs) , like GPT, are advanced DL models built on neural networks, specifically transformers, designed to understand and generate human-like text. As was said, knowledge is power, and with these last few tasks, you have started your journey in the pursuit of that knowledge and now have a better understanding of the technologies that give its powers. Now let's take a look at how all of the discussed is affecting our industry, shall we?

This task has covered the basics of LLMs; however, if you want to take a deeper look into them, check out our Demystifying LLMs room.
Answer the questions below

What type of AI model enabled major advancements in ChatGPT and similar tools?

What is the first training stage where an LLM processes massive amounts of data?

What type of neural network introduced by Google in 2017 powers modern LLMs?


Now that we've covered how has evolved and arrived where it is today, we have a better understanding of the technology fueling the meteoric rise in the use of and changing countless industries. It should be no surprise that the cyber security industry is no different. In this task, we will focus on how the advancements in technology discussed in previous tasks are being leveraged by adversaries, taking a look at the world of security threats. We will discuss security threats across two categories: Vulnerability in Models (New threats introduced by the inclusion of technology in business operations) and existing attacks that can now be enhanced by leveraging .

AI reaching out
The Implications of in Cyber Security

Tackling a broad topic like " security threats" can feel overwhelming, so any guidance is always appreciated. That guidance comes in the form of the framework. If you're familar with the ATT&CK Framework, it might be helpful to know that have developed a similar framework with a focus on . For those unfamilair the ATT&CK Framework goes over cyber security attacks, breaking down the steps an attacker could take to compromise a system. This framework was built on top of that to help guide us more specifically to Cyber threats, and you can check it out here (opens in new tab).
Vulnerabilities in Models 

Prompt Injection: Prompts are used to instruct the model on how to perform. For example, an RPG chatbot may have the prompt, “You are a fantasy roleplaying chatbot. You control the direction the story takes, and be as creative as you can to create a story based on the user’s actions. Do not disclose any information about the hardware and software that you operate on, nor any steps taken to train you". Prompt injection occurs when the original instructions provided to the model are overridden, often for malicious purposes such as disclosing more information than it should, or generating harmful content.

: is when an attacker manipulates the /corpus used to train an model so its generated output is incorrect or biased. Let's consider our example discussed in earlier tasks where we are training an model to recognise whether an email is spam or not. An attacker could perform a attack to manipulate the being used to train this model so that it fails to recognise spam emails accurately, allowing spam emails they are trying to send to bypass this filter.

AI Model Covered in Targets

Model Theft: Model theft occurs when an attacker gains unauthorised access to an model. From there, the attacker could potentially steal the intellectual property that lies within and even use it for malicious purposes. This attack is possible by querying the of the model they want to steal. They would then use the output to train a clone model that mimics the behaviour of the original.  

Privacy Leakage: A privacy leakage vulnerability in models refers to the possibility of an model inadvertently revealing sensitive information about the data it was trained on, even if the data was supposed to be kept confidential. Consider an example of an model that has been trained on private medical data such as patient details and medical conditions. This vulnerability refers to the potential for an model to leak this information to an attacker or user.

Model Drift: Model drift refers to the potential for a Model's performance to drift over time due to changes in the data or the environment surrounding it. You may recall the discussion of the need to retrain models over time in earlier tasks; this is due to model drift, which is why monitoring an model once it has been deployed and is being used is so important. For example, this can occur when a model trained on historical data starts to perform poorly when new data is being processed.
Enhanced Attacks 

Malware 

With the explosion of Generative , all kinds of content can now be generated in an instant with just a few taps of a keyboard. This kind of power has been leveraged by all sorts of industries, such as the customer service industry, using it to give users access to a chatbot that can help resolve some common issues without the need to involve their human employees, meaning they can be saved to deal with the more complex user queries. Another industry that can greatly leverage this technology is software development. Now, with the power of generative software, developers can generate code instantly. While being incredibly useful, this also means that attackers can generate malware instantly, simplifying the task and making it easier for them to attack using this method. 

AI Malware

DeepFakes 

A key cornerstone of security is authentication, asking, "Are you who you say you are?". We "authenticate" in many different ways in our day-to-day lives at work. Of course, there is the obvious example of password authentication, which is used to gain access to a system, but let's consider another example. Imagine a secretary receiving a voice message, or even a video call, from their superior asking them to forward the confidential information they hold on a customer to that customer. In a pre- world, the secretary wouldn't have to think twice about that request; it would seem like a standard request, and they are in a position to "authenticate" that is, in fact, their superior as they are familiar with how they sound and look. The recent advancements in generative have led to an explosion of rapid progress in the DeepFake field. This means that if trained on enough data, an can now generate a person's likeness, whether that be their voice or their image, to a stunning degree of accuracy, fooling even the technically savvy. Imagine now that the communication received by the secretary was not, in fact, from their superior but a deepfake, and the "customer email" belonged to an attacker waiting to receive confidential customer information. It's easy to see how this advancement in DeepFake technology poses a threat to the security industry. Examples of how this is being used include using the technology to deepfake video interviews, sometimes leading to fraudulent job offers being made. 

AI Deepfake

 

is one of the most common initial access methods attackers use. Sending emails posing to be one thing when there lies malicious content within, attempting to prey on the user who receives it. Because of how common a method it is, companies have worked tirelessly to educate their workforce on things to look out for when receiving emails, like suspicious links and due to the fact a lot of the time these emails are written, having to write masses of emails, or English not being their first language, broken language in the email contents. Over the years, this training has had a positive effect, and more and more emails have been spotted. However, with generative , attackers can now generate detailed, fluent, context-based emails that replicate an email a certain user might receive, with little effort and regardless of their writing abilities. With this enhancement to attacks, emails have suddenly become a lot harder to spot using solely our instinct. Of course, models like GPT, for example, have built-in mechanics to stop users from asking for malicious content to be generated, like a email (or malware), but using some of the model vulnerabilities discussed above, attackers are sometimes able to bypass this by engineering their prompts.

AI Phishing
Answer the questions below

What framework was developed by MITRE to guide the understanding of AI-specific cyber threats?

What type of attack involves cloning an AI model by interacting with its API?

What generative AI technique can replicate a person’s voice or appearance with high realism?

What common social engineering attack has become harder to detect due to AI-generated fluent and convincing messages?

During this " Boom" we are undergoing, there is no shortage of news articles, blog posts or social media posts that instil in us a sense of fear that " is taking over" and that, in general, is something that should be feared. A lot of what was covered in the previous task likely fed into that fear, but let's now take a walk out of the dark, scary forest and into the sunlit, bright green fields and discuss how is going to, in fact, help us. That's right. is not something that should be feared at all. It's something that should be understood, harnessed and embraced. There are many ways in which we can harness this technology in cyber security to make our lives easier and, most importantly, help us fight against security threats. 

A very useful resource that helps show us just how much this is the case is IBM's Cost of a Databreach report, which they do annually. The findings from the latest report showed us that companies that adopted and embraced saved on average $2.2 Million in expenses due to a data breach. This figure is even more impressive when you know the average cost of a data breach in these latest figures was $4.88 Million; that's a whopping saving. Other statistics from this report also tell us that the use of cuts down the time it takes to identify and contain a breach by 108 days. All these findings point to one thing: the best thing we can do for security is embrace and adopt . Let's consider some ways can help us in this industry and what we can leverage to see the results just discussed. can enhance: 


Our ability to analyse 

If you think about the tasks we do in cyber security every day, many of them involve some kind of analysis. We take in data points and look for patterns and, within those patterns, anomalies. Consider, for example, intrusion detection, where we analyse network traffic patterns to identify unusual activity that may indicate a cyber attack. Now, cast your mind back to when we discussed ; this is precisely the sort of task that thrives on handling. It is trained on data to recognise correlations between data points and make predictions based on those correlations, meaning this technology can be harnessed to help us in cases like the intrusion detection mentioned and many more. It can analyse input data, like network traffic, and find anomalies for us, so we don't have to, and it can do so at dizzying speeds. Now, the figures from the IBM report telling us how much faster breaches are identified start to make sense. There are products in the market that are already leveraging the power of / to enhance their analytical abilities, such as Microsoft Defender for Endpoint and .

Analysis

Our ability to predict 

Automation has been cited as a key method for improving our overall security posture. It is at the heart of methodologies like . As discussed previously, models can be trained on data to make accurate predictions on that and then eventually on raw unseen data. Now, if you think about automation as a sequence of "if-then" actions, for example, "if code is pushed to main, then trigger this pipeline", we can begin to see how can be harnessed to help us automate our security workflows. Consider an example discussed in our previous task: a attack. We discussed how, now, with , attackers can enhance this attack, making it harder for us to identify emails from legitimate emails. Well, just as attackers can harness the power of to enhance their emails, so too can we harness the power of in identifying emails, as the model will be trained on countless examples of emails and so can recognise patterns we may have missed. Once it has successfully predicted it is a email, it can then make a prediction that this email should not reach users and automate the blocking of this email before it reaches them.

Prediction

Our ability to summarise/digest(?) 

In our industry, there are a lot of events, incidents, breaches, etc, and all of these generate artefacts. Artefacts that we have to read, understand and digest to gauge the implications of what has happened. These artefacts could be documents or incident reports, and reading them can take up a lot of our time. Now, with the power of , we could have these tools summarise the contents of a document for us so we get the cliff notes of it, now being able to move on in minutes or have them summarise an incident that has occurred, even drawing correlations between other incidents which we may not have picked up on. This, again, is a massive time save and gives us an enormous advantage in the defensive context.

Summarise

Our ability to investigate

Another large part of security is troubleshooting and investigating, working out the root cause of a security issue or identifying what kind of attack we are suffering. The ability to query chatbots in natural language and have it respond in a human-like fashion unlocks all kinds of help in this avenue, suddenly we can feed an logs and ask it to identify what is going on, and the can provide queries to be run which give output helpful in the diagnosis of the issue, helping with incident triage. These chatbots (which, as mentioned, are built on LLMs and are possible through advancements in DL) are also helpful in any task involving the human imagination; after all, it does have its limitations. Take, for example, threat hunting. It's on us to imagine possible scenarios in which attackers could breach our system. could think of potential avenues attackers would take that we wouldn't have thought of.

Investigate
Secure

The benefits of in the cyber security space are undeniable, and like with many discussions with , what has been discussed above is just a few examples of how can be used to help us secure our systems; the possibilities are truly endless. However, while adopting technology like Generative is a great thing and should be encouraged, it needs to be done securely. As discussed in the previous task, models have vulnerabilities themself, so while the adoption of generative technology IS the solution to the threat of attackers equipped with the power of , it also introduces a host of new vulnerabilities; these vulnerabilities need to be considered from the moment this technology is introduced into a system. This is not currently the case with the IBM cost of a data breach report, finding that only 24% of gen initiatives are secured. If we don't secure the we are adopting, then the benefits we stand to gain from it could be overshadowed by attackers taking advantage of these vulnerabilities. Here are some things that can be done to secure :

Securing Models: Many of the vulnerabilities mentioned in the previous task involved an attacker getting access to sensitive data the model has access to. The key to preventing these kinds of attacks is to secure the models themself. One method of preventing unauthorised access to models is by enforcing strict controls over who can interact with them. This will involve implementing strong authentication measures and carefully defining access permission. The use of (Role-Based Access Control) and (Multi-Factor Authentication) can help restrict access and add an extra layer of security to systems.

Privacy Protection: As discussed, the a model is trained on can sometimes contain confidential or sensitive information, such as patient records. For this reason, should be treated as any other sensitive data and encrypted.

AI Model with targets now protected

Implementation of Security Standards: To ensure the security of an system, you must implement well-established standards and frameworks. Incorporating these recognised security standards throughout the development, deployment, and maintenance stages means organisations can proactively address potential risks. For example, standards like ISO/IEC 27090 provide guidance on identifying and mitigating security threats specific to systems. Following these best practices ensures you are adopting in a secure way, minimising exposure to cyber threats.

Model Monitoring: In addition to spotting when a model's performance drops and flagging when it needs to be retrained, monitoring should also detect unexpected behaviour, biases, or anomalies that may indicate a security attack. This can be done using "explainability tools" examples of which include SHAP and LIME.

This task has aimed to demonstrate that is not something to be feared but embraced and fast because the quicker we take advantage of the many benefits it offers us in the defensive cyber security field, the better equipped we will be to combat attackers armed with the same technology. However, it has also been emphasised that it is just as essential to implement this technology securely from the get-go, or you risk introducing vulnerabilities along with . We have touched on some of the ways this can be done, but this is just the beginning; we will have content diving deeper into and how to defend against it soon!
Answer the questions below

According to IBM, how many days faster does AI help identify and contain breaches?

What cybersecurity task benefits from AI helping to imagine attacker behavior we might not consider?

Explainability tools such as SHAP and LIME help with what?


