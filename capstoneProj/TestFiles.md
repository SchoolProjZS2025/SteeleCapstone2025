We will not be hosting files because most people cannot download vulnerable files off github from company networks.
Please understand how these files work before utilizing them.


**Clickjacking**
Put the link to your site into the iframe section at the bottom of each file, then save as an html file. Log in to your application, then double click on the following html file so that it opens in the same browser. If you can see your website in the iframe, this proves your application is vulnerable to clickjacking.
The following files come from PortSwigger: https://portswigger.net/web-security/clickjacking

Basic:
test1.html
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

Frame busting:
test2.html
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

**XXE**
Example:

Linux reflected:


Windows reflected:




**XSS**
SVG file:


PDF file:








