This page should be customized by the app team to include resources for writing secure code and avoiding vulnerable code usage. This includes things such as: proper regex filters, common vulnerable regex filters, vulnerable javascript sinks, and other commonly seen code snippets. The goal should be to create a quick reference guide for the dev team that is both application specific and within your company's risk appetite. 


Review the following articles to better understand secure coding practices. The app team should review the OWASP sources to guide this entire page.

High level secure coding: https://www.appsecengineer.com/blog/the-art-of-secure-coding

Digging deeper: https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/assets/docs/OWASP_SCP_Quick_Reference_Guide_v21.pdf

https://owasp.org/www-project-code-review-guide/assets/OWASP_Code_Review_Guide_v2.pdf

Source Code Analysis Labs:

https://github.com/yeswehack/vulnerable-code-snippets

https://pentesterlab.com/badges/codereview

https://www.youtube.com/watch?v=ypNKKYUJE5o

### General Guidance
All SQL queries must utilize parameterized queries.

Source: https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html

New API endpoints should be limited to necessary methods.

Source: https://learn.microsoft.com/en-us/answers/questions/1437604/how-to-disable-some-http-methods-for-a-net-mvc-app

New functions and pages must have authorization in place.

Source: https://learn.microsoft.com/en-us/aspnet/core/security/authorization/policies?view=aspnetcore-9.0

Do not modify critical response headers or cookies.

All user input must be filtered before processing.

### Critical Functions
These Java code snippets can introduce vulnerabilities in our application. Please review any new code for the following snippets. The following snippets were pulled from the resources listed at the top of this document.
```
OS Comm inj:
r.exec();


String[] commands = {args[0]};
Runtime.getRuntime().exec(commands);

Runtime.exec
ProcessBuilder (constructor)

SQL injection:
java.sql.Statement

String sql = "SELECT * FROM users WHERE username = '" + username + "'";
rs = stmt.executeQuery(sql);

Prepared statement(fix):
conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
String sql = "SELECT * FROM users WHERE username = ?";
pstmt = conn.prepareStatement(sql);
pstmt.setString(1, username);
rs = pstmt.executeQuery();

Deserialization:
Object deserializedObject = ois.readObject();

Flawed Encryption:
DES
random() or random.

Missing Access Restrictions, start by searching for the following:
java.security.AccessController.doPrivileged
return AccessController.doPrivileged
PrivilegedExceptionAction
PrivilegedAction
AccessControlContext

```
#### Javascript
Don't allow untrusted user input in the following functions.
```
eval()
innerHTML
```

**Additional resources**

https://www.iothreat.com/blog/dangerous-js-functions
https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html

#### Regex Filtering
If you would like to see specific examples of attacker payloads, visit the following link. This may help determine what characters should be allowed in your specific context.

https://github.com/swisskyrepo/PayloadsAllTheThings

The following regex filters may cause a denial of service.

Source:  https://pentesterlab.com/badges/codereview
```
/^dev-(\w+)+\d+\.website\.com$/  
(a+)+
([a-zA-Z]+)*
(a|aa)+
(a|a?)+
(.*a){x} for x \\> 10
```

Allowed regex:
```^[a-zA-Z0-9 ]*$```

### Remediation Guidelines
Include article specific to your environment.

Complete input validation guide: https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html

Parameterized query guide for multiple languages: https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html

### Other articles:
**Java**

https://blog.codacy.com/java-vulnerabilities

https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html

**Multi-language vulnerable code labs**

https://github.com/yeswehack/vulnerable-code-snippets

**.NET**

https://james-joseph.medium.com/owasp-top-10-vulnerabilities-in-net-core-7-and-how-to-beat-them-2f27c38fb60b

http://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html