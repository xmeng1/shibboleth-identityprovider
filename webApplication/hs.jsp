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
	<title>Access Request</title>
</head>

<body onLoad="document.forms[0].submit()">

<h1>Inter-institutional Access Request</h1>

<p><bean:write name="hs_helpText" /></p>
<p>
<form name="shib"  action="<bean:write name="shire" />" method="POST">
<input type="hidden" name="TARGET" value="<bean:write name="target" />">
<input type="hidden" name="SAMLAssertion"value="<bean:write name="assertion" />">
<input type="submit" value="Transmit">
</form>
</p>
<p><a href="<bean:write name="hs_detailedHelpURL" />">Detailed information</a> explaining this process.</p>

</body>
</html>