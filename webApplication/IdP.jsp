<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">
    
    <%
		response.setHeader("Expires","19-Mar-1971 08:23:00 GMT");
		response.setHeader("Cache-control","no-cache");
		response.setHeader("Pragma","no-cache");
	%>
    <%@ taglib uri="/WEB-INF/tlds/struts-logic.tld" prefix="logic" %>
    <%@ taglib uri="/WEB-INF/tlds/struts-bean.tld" prefix="bean" %>

    <jsp:useBean id="shire" scope="request" class="java.lang.String" />
    <jsp:useBean id="target" scope="request" class="java.lang.String" />
    <jsp:useBean id="assertion" scope="request" class="java.lang.String" />
    <jsp:useBean id="hs_helpText" scope="application" class="java.lang.String"/>
    <jsp:useBean id="hs_detailedHelpURL" scope="application" class="java.lang.String"/>
	
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
<head>
    <link rel="stylesheet" type="text/css" href="main.css" />
    <title>Shibboleth Handle Request Processed</title>
</head>

<body onload="document.forms[0].submit()">

<% 
	if (request.getAttribute("shire") == null
		|| request.getAttribute("shire").equals("")
		|| request.getAttribute("target") == null
		|| request.getAttribute("target").equals("")
		|| request.getAttribute("assertion") == null
		|| request.getAttribute("assertion").equals("")) 
	{
		request.setAttribute("requestURL", request.getRequestURI()); 
		request.setAttribute("errorText", "This page cannot be accessed directly"); 
        request.getRequestDispatcher("/IdPError.jsp").forward(request, response);
	}
%>

<h1>Shibboleth Handle Request Processed</h1>

<script type="text/javascript">
<!--	
document.write("<p>You are automatically being redirected to the requested site. ");
document.write("If the browser appears to be hung up after 15-20 seconds, try reloading ");
document.write("the page before contacting the technical support staff in charge of the ");
document.write("desired resource or service you are trying to access.</p>");
document.write("<h2>Redirecting to requested site...</h2>");
// -->
</script>

<noscript>
<p>
<strong>Note:</strong> Since your browser does not support JavaScript, you must press the
Continue button once to proceed to the requested site.
</p>
</noscript>


<form id="shibboleth"  action="<bean:write name="shire"/>" method="post">
<div>
<input type="hidden" name="TARGET" value="<bean:write name="target" />" />
<input type="hidden" name="SAMLResponse" value="<bean:write name="assertion" />" />
</div>
<noscript>
<div>
<input type="submit" value="Continue" />
</div>
</noscript>

</form>
</body>
</html>
