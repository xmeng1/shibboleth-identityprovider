<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html 
	PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" 
	"DTD/xhtml1-strict.dtd">
	<%@ taglib uri="/WEB-INF/tlds/struts-logic.tld" prefix="logic" %>
	<%@ taglib uri="/WEB-INF/tlds/struts-bean.tld" prefix="bean" %>
	<jsp:useBean id="originsets" scope="application" class="edu.internet2.middleware.shibboleth.wayf.OriginSet[]"/>
	<jsp:useBean id="requestURL" scope="request" class="java.lang.String"/>
	<jsp:useBean id="helpText" scope="application" class="java.lang.String"/>
	<jsp:useBean id="supportContact" scope="application" class="java.lang.String"/>
	<jsp:useBean id="shire" scope="request" class="java.lang.String"/>
	<jsp:useBean id="target" scope="request" class="java.lang.String"/>
	<jsp:useBean id="encodedShire" scope="request" class="java.lang.String"/>
	<jsp:useBean id="encodedTarget" scope="request" class="java.lang.String"/>
	<jsp:useBean id="searchResultEmptyText" scope="application" class="java.lang.String"/>
	<jsp:useBean id="logoLocation" scope="application" class="java.lang.String"/>
	<logic:present name="searchresults" scope="request">
		<jsp:useBean id="searchresults" scope="request" class="edu.internet2.middleware.shibboleth.wayf.Origin[]"/>
	</logic:present>
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
	<link rel="stylesheet" type="text/css" href="main.css" />
	<title>Access Request</title>
</head>

<body>

<div class="head">

<img src="<bean:write name="logoLocation" />" alt="Logo" />
<h1>Inter-institutional Access Request</h1>
<p class="text"><bean:write name="helpText" /></p>
</div>

<div class="search">

	<logic:present name="searchResultsEmpty" scope="request">
		<p class="error"><bean:write name="searchResultEmptyText" /></p>
	</logic:present>
	
	<logic:present name="searchresults" scope="request">
		<ul>
		<logic:iterate id="currResult" name="searchresults">
			<li>
			<a href="<bean:write name="requestURL" />?action=selection&amp;origin=<jsp:getProperty name="currResult" property="urlEncodedName" />&amp;shire=<bean:write name="encodedShire" />&amp;target=<bean:write name="encodedTarget" />"><jsp:getProperty name="currResult" property="name" /></a>
			</li>
		</logic:iterate>
		</ul>		
	</logic:present>
	<form method="get" action="<bean:write name="requestURL" />">
		<p>
			<input type="hidden" name="shire" value="<bean:write name="shire" />" />
			<input type="hidden" name="target" value="<bean:write name="target" />" />
			<input type="hidden" name="action" value="search" />
			<input type="text" name="string" />
			<input type="submit" value="Search" />
		</p>
	</form>
	
</div>

<div class="list">

<logic:iterate id="originset" name="originsets">
<h2><jsp:getProperty name="originset" property="name" /></h2>
<form method="get" action="<bean:write name="requestURL" />">
<p>
<input type="hidden" name="shire" value="<bean:write name="shire" />" />
<input type="hidden" name="target" value="<bean:write name="target" />" />
<input type="hidden" name="action" value="selection" />
<select name="origin">
	<logic:iterate id="origin" name="originset" property="origins">
		<option value="<jsp:getProperty name="origin" property="name" />">
		<jsp:getProperty name="origin" property="name" />
		</option>
	</logic:iterate>
</select>
<input type="submit" value="Select" />
</p>
</form>
</logic:iterate>

</div>

<p class="text">Need assistance? Send mail to <a href="<bean:write name="supportContact" />"><bean:write name="supportContact" /></a> with description.</p>


</body>
</html>