<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html 
	PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" 
	"DTD/xhtml1-strict.dtd">
	<%@ taglib uri="/WEB-INF/tlds/struts-logic.tld" prefix="logic" %>
	<%@ taglib uri="/WEB-INF/tlds/struts-bean.tld" prefix="bean" %>
	
	<jsp:useBean id="requestURL" scope="application" class="java.lang.String"/>
	<jsp:useBean id="errorText" scope="request" class="java.lang.String"/>
	<jsp:useBean id="supportContact" scope="application" class="java.lang.String"/>
	<jsp:useBean id="logoLocation" scope="application" class="java.lang.String"/>
	
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
	<link rel="stylesheet" type="text/css" href="main.css" />
	<title>Access System Failure</title>
</head>

<body>
<div class="head">
<img src="<bean:write name="logoLocation" />" alt="Logo" />
<h1>Inter-institutional Access System Failure</h1>
</div>

<p>The inter-institutional access system experienced a technical failure.</p>

<p>Please email <a href="mailto:<bean:write name="supportContact" />"><bean:write name="supportContact" /></a> and include the following error message:</p>

<p class="error">WAYF failure at (<bean:write name="requestURL" />)</p>

<p><bean:write name="errorText" /></p>


</body>
</html>