<%
response.setHeader("Expires","19-Mar-1971 08:23:00 GMT");
response.setHeader("Cache-control","no-cache");
response.setHeader("Pragma","no-cache");
%>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html 
	PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" 
	"DTD/xhtml1-strict.dtd">
	<%@ taglib uri="/WEB-INF/tlds/struts-logic.tld" prefix="logic" %>
	<%@ taglib uri="/WEB-INF/tlds/struts-bean.tld" prefix="bean" %>
	
	<jsp:useBean id="shire" scope="request" class="java.lang.String" />
	<jsp:useBean id="target" scope="request" class="java.lang.String" />
	<jsp:useBean id="assertion" scope="request" class="java.lang.String" />
	<jsp:useBean id="hs_helpText" scope="application" class="java.lang.String"/>
	<jsp:useBean id="hs_detailedHelpURL" scope="application" class="java.lang.String"/>
	
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
	<link rel="stylesheet" type="text/css" href="main.css" />
	<title>Shibboleth Handle Request Processed</title>
</head>

<body onLoad="document.forms[0].submit()">

<h1>Shibboleth Handle Request Processed</h1>

<!-- <p><bean:write name="hs_helpText" /></p> -->

<p>You are automatically being redirected to the requested site. Please wait
a few seconds before pressing the Continue button, if the browser appears to
be hung up.</p>

<noscript>
<blockquote>
<b>Note:</b> Since you have disabled JavaScript in your browser, you must press the
Continue button once to proceed to the requested site.
</blockquote>
</noscript>

<p align="center">
<form name="shib"  action="<bean:write name="shire" />" method="POST">
<input type="hidden" name="TARGET" value="<bean:write name="target" />">
<input type="hidden" name="SAMLResponse" value="<bean:write name="assertion" />">
<input type="submit" value="Continue">
</form>
</p>
<!--
<p><a target="help" href="<bean:write name="hs_detailedHelpURL" />">Detailed information</a> explaining this process.</p>
-->

</body>
</html>
