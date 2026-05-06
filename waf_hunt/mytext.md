ou begin your penetration test expecting a hardened web application, only to compromise it with a simple injection. How? The Web Application (WAF) was absent, misconfigured, or bypassed. Despite being a staple of modern security architecture, WAFs are often misunderstood: they are usually treated as magic shields when, in fact, they are complex systems with strengths, limitations, and blind spots.

Illustration of a brick wall with a flame icon, representing a network firewall.
Learning Objectives

This room introduces WAFs for cyber security practitioners who are already familiar with network and web application security but have not yet explored how WAFs operate under the hood. After completing this room, you will learn about:

    The evolution of firewalls from basic packet filters
    How WAFs detect threats using signatures and behavioural analysis
    Fingerprinting WAFs in real engagements using passive and active techniques
    Analysing WAF rules and anticipating bypass opportunities
    Dissecting real-world rules from the Core Rule Set (CRS)
    Assessing WAF limitations

Prerequisites

Before going through this room, users are expected to have a good understanding of:

    Networking
    How Websites Work
    in Detail
    Firewalls or at least Fundamentals

Answer the questions below

What does WAF stand for? WAF stands for Web Application Firewall.
,


Stateless Firewalls: The Gatekeeper with No Memory

As the name implies, a stateless packet filter or is stateless; it is a gatekeeper with no memory. It operates at Layers 3 and 4 of the OSI model, where it can inspect IP addresses, and ports, some headers, and other protocols. This basic packet filter is entirely ignorant of the context of the traffic; every packet is judged in isolation. Think of a border agent looking at a child’s passport as if the child is travelling alone.

This security measure worked for a while until attackers realised that they could abuse the fact that it is stateless. In other words, an attacker would send a packet with the ACK flag set to trick the into treating the packet as if it were part of an established connection. Because this does not keep track of established connections, it may allow it to pass. It became clear that a more intelligent was necessary.
Stateful Firewalls: Remembering the Conversation

By the mid-1990s, as attacks became increasingly complex, a new model emerged: the stateful . Unlike stateless firewalls, which inspect each packet in isolation, stateful firewalls keep track of active connections, which allows them to better judge a packet before letting it pass through. Think of it as the being able to answer the question, “Does this packet belong to a legitimate ongoing conversation?”

Because they track ongoing sessions, forging a packet with an ACK flag set can no longer trick the into treating it as if it were part of an established connection. Moreover, out-of-sequence packets, among other anomalies, can be detected and dropped. In other words, if the allows outbound traffic to port 443, an outside attacker cannot simply send a packet with a source port of 443, set the ACK flag, and trick the into treating it as part of a legitimate ongoing connection. Being aware of established connections significantly improved the ’s efficiency.
Firewalls that Understand Layer 7

As the need for improved security increased, new technologies emerged on the market. Before exploring Web Application Firewalls (WAFs) in the next task, let’s revisit three more types of firewalls:

    Application-Level Gateway ( )
    Deep Packet Inspection ()
    Next-Generation (NGFW)

Application-Level Gateway

The Application-Level Gateway (ALG) is also referred to as a . One way to think of it is like a protocol interpreter. It is like a diplomatic interpreter who listens to your message and repeats it, ensuring that it does not contain any hidden slurs or secret codes. Unlike stateful firewalls that merely track connections, ALGs terminate incoming connections and initiate new ones on the client’s behalf. This setup provides them with complete visibility into application-layer protocols, such as and , among others. Consequently, they can validate command syntax and sanitise payloads. While superseded mainly by more scalable technologies, ALGs have laid the conceptual groundwork for Layer 7 inspection, showing that to defend an application, one must speak its language.

Deep Packet Inspection

Stateful firewalls inspect IP addresses and ports; Deep Packet Inspection () firewalls examine the contents of the message itself. goes beyond headers to scan the actual payload of packets, looking for telltale byte sequences of malware, peer-to-peer traffic, or encrypted command-and-control beacons. Crucially, isn’t a standalone architecture but a capability embedded within modern threat prevention systems. For example, it might flag a seemingly benign stream because its matches that of known ransomware traffic, or block a disguised Tor connection hidden within HTTPS. However, alone lacks contextual awareness: it can detect a UNION SELECT in a packet. Still, it cannot determine if it’s part of a legitimate database administrator query or an attack, unless paired with protocol understanding. This limitation is precisely why evolved into something more: the Next-Generation .

Next-Generation

Enter the Next-Generation (NGFW), a stateful that decided to get a PhD in context. An NGFW doesn’t just ask, “Where is this traffic going?” It asks, “Who is sending it? What application is it using? Is it encrypted, and can I decrypt it safely? Should this user even be accessing this service?” By fusing stateful inspection, integrated intrusion prevention (), SSL/ decryption, and identity awareness (via Active Directory, certificates, or SAML), NGFWs enforce policies based on users and applications, not just IP/port tuples. Yet despite their power, NGFWs still treat as one of many protocols. When it comes to defending against logic-based web app exploits (e.g., parameter tampering, injection), they often lack the granularity of a purpose-built WAF.

The table below summarises the five types that we reviewed in this task.
Type 	OSI Layer(s) 	Key Capability
Stateless Packet Filter 	L3–L4 	Filters individual packets based solely on static rules (source/destination IP, port, protocol). No session or flow awareness.
Stateful Inspection 	L3–L4 	Maintains a state table of active connections; validates packets against expected //ICMP state (e.g., flags, sequence).
Application-Level Gateway ( ) 	L7 (protocol-specific) 	Acts as an intermediary; terminates and re-initiates application-layer sessions (e.g., , ). Can inspect and sanitise protocol commands.
Deep Packet Inspection () 	L3–L7 	Inspects packet payloads (not just headers) for known patterns (e.g., malware signatures, P2P protocols). Often integrated into NGFWs.
Next-Generation (NGFW) 	L3–L7 + Identity 	Combines stateful inspection, , integrated intrusion prevention (), SSL/ decryption, and user/application identification (via , certificates, etc.). May include basic WAF modules.

Signature-Based Detection

A signature-based detection engine works by comparing the contents of each packet against a list of known malicious signatures. Generally speaking, such detection engines recognise what’s malicious and rely on this knowledge to decide what’s benign. For example, it would include rules that match patterns, such as the one in this Request: GET /search?q=' OR 1=1-- HTTP/1.1. Moreover, the WAF will respond with something such as 403 Forbidden if the received request matches the rule. Consequently, any similar attacks will be blocked unless the attacker finds a way to evade the rule.

Attackers evade signature rules using:

    Encoding: An attacker might attempt encoding ' OR 1=1-- as '%20OR%201=1--, %27%20OR%201%3D1--, or even %27%20OR%201%3D1%2D%2D.
    Case variation: In this evasion attempt, the attacker would type UNION SELECT as unIOn sElEcT
    Comment insertion: The attacker would attempt to insert comments to evade triggering the rule.
    Alternative syntax: If the attacker can replace one syntax with another, such as 1' AND SLEEP(10)-- with 1' AND IF(1=1, SLEEP(10), 1) --, they might succeed in escaping detection.

For the attacker to succeed, once they determine that a rule is blocking their payload, they need to make various changes and try again. Depending on the target WAF’s rules, they may be able to evade detection. The main advantage of signature-based detection is that the number of false positives, i.e., normal traffic incorrectly detected as malicious, is expected to be low. Furthermore, the rules are relatively manageable to write and understand. Finally, they can run as fast as the running code can match the incoming traffic. The disadvantages mainly lie in the fact that signature-based detection engines are as good as their signatures. Consequently, they might miss malicious payloads due to encoding or other related techniques. Needless to say, they cannot detect an attack if it is not within their signature database; therefore, they cannot detect zero-day attacks and require constant updates. A summary is provided in the table below.
Advantages 	Disadvantages
Low false positives (when tuned) 	Blind to obfuscation (e.g., encoding, comments)
Easy to write and understand 	Can’t detect zero-day attacks
High performance (regex engines are fast) 	Requires constant updates
Behavioural Detection

Behavioural detection is also known as anomaly-based detection. Generally speaking, such kinds of detection engines are trained to know what’s normal. Any deviation from normal is going to be flagged as an anomaly. To build a baseline for normal, exposing the engine to “normal traffic” is indispensable. Normal behaviour can include input length, parameter count, data types, session rate, and historical user behaviour, among others.

Let’s say that a standard HTTP POST request is expected to look like username=alice&password=pass1234, then the detection engines receive something such as username=' OR '1'='1&password=somepass; the existence of special characters in the username, along with white space, is an apparent deviation from what a normal username should be.

The main strength of anomaly-based detection is that it has a decent chance of blocking unknown and zero-day attacks, as such attacks deviate from normal behaviour. Furthermore, they are better at detecting malicious traffic even when encoding and similar tricks are employed. Finally, the detection engine will adapt to the application and get better over time. The main disadvantage is that a high false positive rate is expected, despite the necessity of undergoing a training period. It is also worth noting that, compared to signature-based detection, anomaly-based detection tends to be computationally more expensive. A summary is shown in the table below.
Advantages 	Disadvantages
Catches unknown (zero-day) attacks 	High false positives (e.g., blocks legitimate long forms)
Harder to bypass with simple encoding 	Requires training period (“learning mode”)
Adapts to application logic over time 	Computationally expensive
Hybrid Detection

In many modern commercial WAFs, a combination of both of the previous approaches is used. For example, the traffic might first undergo a fast signature check. Following this step, a deep inspection is conducted to determine the anomaly scoring, and finally, a weighted risk score is calculated to decide on the packet.
Answer the questions below

Which detection method uses known attack patterns?

What kind of attacks can behavioural detection catch that signature-based cannot?


Example Real Rule

The best way to learn about rules is to dive into one. The following rule is for and it is from ® CRS v3.3.7 (opens in new tab).

SecRule REQUEST_BASENAME "@detectSQLi" \
    "id:942101,\
    phase:2,\
    block,\
    capture,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,\
    msg:'SQL Injection Attack Detected via libinjection',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'OWASP_CRS',\
    tag:'capec/1000/152/248/66',\
    tag:'PCI/6.5.2',\
    tag:'paranoia-level/3',\
    ver:'OWASP_CRS/3.3.7',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.anomaly_score_pl3=+%{tx.critical_anomaly_score}'"

The Trigger: SecRule REQUEST_BASENAME "@detectSQLi"

In the first line, we have the following:

    SecRule: Standard ModSecurity directive to define a rule
    REQUEST_BASENAME: This variable refers to the filename or endpoint in the URL path. For example, in /api/user/123, the basename is 123
    "@detectSQLi": This is a call to libinjection, a specialised C library designed only for detecting SQL injection. It is worth noting that libinjection tokenises input like a real SQL parser, instead of matching strings like ' OR 1=1

Rule Metadata: Identity, Context, and Compliance

In the next four lines, we have the following:

    id:942101: Unique identifier (part of CRS numbering scheme)
    phase:2: Run during request body processing (after headers, before app logic)
    block: Take action: reject the request
    capture: Save the matched payload for logging (%{TX.0})

Input Normalisation: Seeing Through the Noise

Before @detectSQLi runs, the input is normalised through a pipeline of transformations:

    t:none: Start with raw input (no auto-decoding)
    t:utf8toUnicode: Convert UTF-8 sequences (e.g., %C2%A7) to Unicode to prevent bypass via encoding
    t:urlDecodeUni: Perform recursive URL decoding (handles double-encoding like %2527 is decoded to %27, which in turn, is decoded to ')
    t:removeNulls: Strip null bytes (%00), often used to terminate strings in C-based parsers

It is crucial to decode the contents before checking; otherwise, it would be easy to miss the encoded threats.

Logging and Attribution: Making Incidents Actionable

In the following two lines, we log a human-readable alert.

msg:'SQL Injection Attack Detected via libinjection',\
logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\

    msg: Human-readable alert that shows up in logs and SIEM.
    logdata: Rich forensic detail:
        %{TX.0}: The exact payload that triggered the rule (thanks to capture).
        %{MATCHED_VAR_NAME}: Which variable was inspected (REQUEST_BASENAME).
        %{MATCHED_VAR}: The full value (e.g., 1' OR '1'='1).

Tags: Connecting to Standards and Strategy

Now it is time to tag the traffic. It is worth noting that the tags are not merely labels; they’re operational hooks in some way. Consider the following example:

tag:'attack-sqli'
tag:'OWASP_CRS'
tag:'capec/1000/152/248/66'
tag:'PCI/6.5.2'
tag:'paranoia-level/3'

The above lines indicate the following:

    capec/1000/152/248/66: Links to CAPEC (opens in new tab) (Common Attack Pattern Enumeration) – useful for threat modelling.
    PCI/6.5.2: References PCI DSS requirement for protecting against injection flaws.
    paranoia-level/3: CRS uses four paranoia levels. PL3 is stricter and blocks more, but has higher false positives. Used in high-security environments. You can learn more about paranoia levels here (opens in new tab).

Scoring and Telemetry: Feeding the Anomaly Engine

Finally, we can use the detected traffic to update our risk score. Take a closer look at the following two lines:

setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}' setvar:'tx.anomaly_score_pl3=+%{tx.critical_anomaly_score}'

They achieve the following:

    tx.sql_injection_score: Tracks cumulative SQLi risk across multiple rules.
    tx.anomaly_score_pl3: Feeds into CRS’s total anomaly score for paranoia level 3.

After studying this rule for detecting in a modern system, you can see that it embodies modern WAF design, including specialised detection, deep normalisation, contextual logging, and integration into a scoring system. It’s not only a blocking traffic; it serves as a sensor in a larger security system.
Answer the questions below

Which library does OWASP CRS use to detect SQLi?

What transformation handles double URL encoding?

What score is increased when a critical rule triggers?

Log in to the dashboard at http://10.81.138.158:7000. Under Attack Control, click Critical Attack, locate the attack that triggered rule 932160 at 2025-11-12 15:38:00. What is the URI that triggered this rule? You need to click View to see the request details.

Before concluding this room, it is worth visiting some of the limitations of WAFs.

WAFs Only Work If Rules Are Good

WAFs are as good as their rules. Although this may seem obvious, it is worth emphasising here: signature-based rules are likely to miss new payloads. Obfuscation, via encoding, comments, or even white-space, can make it possible to evade regex-based rules. Furthermore, a sizable number of organisations run WAFs in log-only mode due to the high rate of false positives, rendering them useless for protection.

WAFs Don’t Understand Application Logic

One of the biggest misconceptions when setting up a WAF is that it can stop all web attacks. This expectation is unrealistic. Because WAFs don’t understand the application logic, they cannot determine if a user should be allowed to edit another person’s profile or if a price parameter (?price=1.99) has been tampered with. These are business logic flaws, and WAFs are blind to them.

Consider the following example of real-world impacts:

    IDOR (Insecure Direct Object Reference): In the HTTP Request GET /api/user/123, if the attacker changes 123 to 124, where no special characters or malicious payloads were used. Consequently, nothing would trigger a WAF to block it.
    Authorisation bypass: If a user can access /admin without being an admin, the URL looks benign, and the WAF cannot detect anything wrong.
    Race conditions and replay attacks: Similarly, such attacks don’t involve any malicious syntax for the WAF to detect.

In brief, WAFs filter syntax, not intent. They can’t fix broken access controls.

Encrypted Traffic Is a Blind Spot

Unless decrypted, encrypted traffic cannot be inspected for malicious payloads; therefore, modern WAFs sit in front of the termination points to monitor all the traffic. However, if encryption occurs before the WAF, the WAF would only see encrypted blobs and not the actual requests.

It should be noted that when is terminated at the WAF, certificate management adds to the complexity and risk of the setup. Furthermore, some organisations avoid decryption due to privacy or compliance concerns.

Client-Side Attacks Fly Under the Radar

WAFs inspect server-bound traffic; consequently, we cannot expect them to block attacks happening entirely in the browser. For example, in a DOM-based attack, the payload executes in the browser and is never sent to the server. Also consider malicious first-party scripts, such as compromised analytics libraries; these don’t generate suspicious server requests for the WAF to intercept.

WAFs Introduce New Attack Surfaces

Ironically, adding a WAF introduces new attack surfaces. In fact, poorly configured custom rules can introduce , for example, by dynamically constructing ModSecurity rules and failing to properly escape input. Also, care should be taken that a complex regex or large payloads do not lead to due to memory exhaustion.

Furthermore, if the management interface is exposed on a public IP address, the attacker would gain access to a new WAF admin login page, allowing them to brute-force its login credentials. Or worse, the management user interface might be vulnerable to an vulnerability, as in the case of -2020-5902.

Performance vs. Security Trade-Off

It is worth noting that deep packet inspection incurs time costs. Consider the cases where the WAF needs to do regex matching on large payloads or decode multi-layered encoding. This procedure may impact overall performance and introduce a delay. For anomaly-based detection, running behavioural models or engines also requires a non-trivial share of the system resources. As traffic scales, it is essential to watch for increases in latency or legitimate requests timing out.

Finally, deploying a WAF or any other security solution does not mean that the systems become miraculously secure. One should be careful not to fall into a false sense of security. On one hand, a properly configured WAF will add to the security, and it will even help meet compliance requirements; however, cyber security is built through a comprehensive security policy and various security solutions.
Answer the questions below

What prevents WAFs from inspecting traffic if not terminated at the WAF?