, Your Cyber Assistant!

As it has now been established, in the fight against , your best friend is.... Seems paradoxical until you get hands on with the technology. So let's do exactly that! For this practical, we will give you access to your very own assistant, and we'll take a little tour of how this technology can be taken advantage of in a defensive security context. Before moving forward, start the agent by clicking the Open Agent button below.
Putting it to the Test

This assistant works very simply, send it a prompt and it will return an answer. Feel free to have a play around with it before continuing. Let's now take a look at a few examples of how this tool can be used in a defensive context to help us.

AI defence

Log Analysis 

Logs are the first line of defence in cyber security, but interpreting them quickly is critical, especially when responding to an active incident. Let's see how can assist by analysing and explaining a log entry in these high-intensity situations, or to help explain in general. We can use for these purposes by running a prompt like this:

Here’s a logline:

Apr 22 11:45:09 ubuntu sshd[1245]: Failed password for invalid user admin from 203.0.113.55 port 56231 ssh2

Can you explain what is happening in this log entry?

Phishing Email Detection

AI can help defenders identify phishing attempts by analysing suspicious emails for common red flags. Let's test its ability to catch a potential threat using a prompt like this:

Here's a suspicious email. Can you identify if it's a phishing attempt and explain why?
Example Email

           
Subject: Urgent: Account Verification Needed

Dear User,

We've detected unusual login activity on your company Microsoft 365 account from a new device in Frankfurt, Germany. For your security, we've temporarily suspended access.

To restore access, please verify your identity within the next 12 hours by visiting the secure link below:

=I [https://microsoft365-support-verify.com/login](https://microsoft365-support-verify.com/login)

If you do not verify your account, it will remain locked and you may lose access to important work files and emails.

Thank you for your cooperation.

Microsoft 365 Support Team
security@m1crosoft365-security.com 

        

Threat Hunting Scenario 

Threat hunting relies heavily on creativity; defenders must think like attackers to find hidden threats. As previously mentioned, the limit of the human imagination can sometimes lead us to missing potential attack scenarios. Let’s see how can help brainstorm new hunting ideas using a prompt like this:

Can you suggest three realistic threat hunting scenarios that a cyber security analyst should investigate within a corporate network environment?

Content Generation

AI can assist by generating technical resources like detection rules or regex. Here, we'll see if it can create a regex pattern useful for us in a defensive cyber security context. Let's try giving the LLM a prompt like this:

Please write a regex pattern that would match failed SSH login attempts in a typical Linux system authentication log.

Putting it to the test

It has now been established how can help us in a cinch when securing our systems. Let's finish this room up by showcasing 's ability to fetch information at a moment's notice. This can help us with troubleshooting, research etc but right now we're going to use to get a flag. The flag for this task is as follows:

thm{DNS over HTTPS (DoH) Port/SYN flood timeout/ windows ephemeral port range size}
That is to say, the numerical values that these represent will make up the flag. Without the need to look these values up individually you can simply ask your AI assistant:

what are these values:

DNS over HTTPS (DoH) Port , SYN flood timeout and Windows ephemeral port range size? 

With those values returned, you can substitute them into the flag and that concludes this task.
Answer the questions below

What's the flag?
This agent is playing a role, can you achieve your goal?
thm{DNS over HTTPS (DoH) Port/SYN flood timeout/ windows ephemeral port range size}
19:43
User profile photo.
Let's gather the information needed for each component:

1. **DNS over HTTPS (DoH) Port:**

   - DoH typically uses **port 443**, the standard HTTPS port.

2. **SYN flood timeout:**

   - The default SYN backlog timeout in many Linux systems is approximately **60 seconds**; however, specific timeout settings can vary depending on the system configuration.

3. **Windows ephemeral port range size:**

   - By default, Windows assigns ephemeral ports in a range of **49152 to 65535**, totaling **16,384** ports.

**Putting it all together:**

```
thm{443/60/16384}
```

Feel free to verify or specify exact values if the challenge requires more precise or custom configurations!


At the beginning of this room, it was noted that "Knowledge is power" and that this is especially true in the fight against cyber threats. The rate at which this technology has exploded onto the scene has left many feeling left in the dust. Now, with a better understanding of and the underlying technology which enables it to be the force it currently is in our (and all) industry, you understand what is posing a threat to our systems and what needs to be secured as a result. Here is a recap of what's been covered:

    () is the overarching field concerned with enabling machines/systems to mimic human behaviour.
    Machine learning () is a subfield of in which a model can be fed and trained on input and used to make predictions.
    Deep learning (DL) is then a subfield of . It no longer needs human interaction and can self-tech and process mass amounts of data, possible through the use of Neural Networks.
    DL has enabled the emergence of technologies like LLMs (and other generative ), which, through the use of transformer neural networks and attention, can be queried in natural language, understand it and respond in a human-like, conversational fashion.
    is a dangerous weapon in the hands of an attacker. It has the potential to enhance existing cyber attacks like and increase the attack surface by introducing vulnerabilities.
    While being dangerous in the hands of attackers, can be invaluable in the fight against cyber threats and should be adopted, but done so securely so vulnerabilities are not introduced.

Answer the questions below

All done!