# Web Application Penetration Testing Crash Course For Developers

This GitHub repo contains all necessary material utilized in the following developer focused web application penetration testing course:
[https://www.youtube.com/watch?v=oNDEU_uNtzI&list=PLqPCUirqsN_x_seY51DiivfV-CjgJDKUp](https://www.youtube.com/watch?v=TcrWRL9CZh8&list=PLqPCUirqsN_x_seY51DiivfV-CjgJDKUp)

The items in this course are not covered in order of risk rating. The ratings provided in the checklist were mostly generating using CVSS V3.1 average scores for 2025 CVEs. Please use the following tools to create ratings that more accurately represent your application and companies risk appetite:

https://owasp.org/www-community/OWASP_Risk_Rating_Methodology

https://www.first.org/cvss/calculator/4-0


Quick breakdown of the video series:

Intro - In progress.

Tools - Introduction to the tools used throughout the course. Not a required watch if you already have a Postman/Insomnia/SoapUI project for testing your application.

Continuous Monitoring - Covers the first section of the checklist. These items should be in the back of your mind as you continue testing the other checklist items.

Response Headers - Covers response header risks and identifying common misconfigurations.

Cookie Checks - Reviewing cookie attributes.

Code Review Resources - A high level recommendation for app teams to build out a code review document for their teams. This page is not a template or a comprehensive list of resources, just a starting point.

The next set of videos utilize the payload lists provided in this GitHub repo to dynamically test for common vulnerabilities. This includes cross-site scripting, SQL injection, directory traversal, etc.

Login Pages - Covering common vulnerabilities surrounding login functionality.

Session Management - Testing session functionality without using malicious payloads or automated tools.

Misc - Common vulnerabilities that do not fit neatly into the above categories.
