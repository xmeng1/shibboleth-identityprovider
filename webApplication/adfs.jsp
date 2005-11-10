<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">
    
    <%
		response.setHeader("Expires","19-Mar-1971 08:23:00 GMT");
		response.setHeader("Cache-control","no-cache");
		response.setHeader("Pragma","no-cache");
	%>
    <%@ taglib uri="/WEB-INF/tlds/struts-logic.tld" prefix="logic" %>
    <%@ taglib uri="/WEB-INF/tlds/struts-bean.tld" prefix="bean" %>

    <jsp:useBean id="wreply" scope="request" class="java.lang.String" />
    <jsp:useBean id="wa" scope="request" class="java.lang.String" />
    <jsp:useBean id="wresult" scope="request" class="java.lang.String" />
    <jsp:useBean id="hs_helpText" scope="application" class="java.lang.String"/>
    <jsp:useBean id="hs_detailedHelpURL" scope="application" class="java.lang.String"/>
	
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
<head>
    <link rel="stylesheet" type="text/css" href="main.css" />
    <title>ADFS Authentication Request Processed</title>
</head>

<body onload="document.forms[0].submit()">

<% 
	if (request.getAttribute("wa") == null
		|| request.getAttribute("wreply").equals("")
		|| request.getAttribute("wresult") == null) 
	{
		request.setAttribute("requestURL", request.getRequestURI()); 
		request.setAttribute("errorText", "This page cannot be accessed directly"); 
        request.getRequestDispatcher("/IdPError.jsp").forward(request, response);
	}
%>

<h1>ADFS Authentication Request Processed</h1>

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


<form id="adfs"  action="<bean:write name="wreply"/>" method="post">
<div>
<input type="hidden" name="wa" value="<bean:write name="wa" />" />
<logic:present name="wctx" scope="request">
	<input type="hidden" name="wctx" value="<bean:write name="wctx" />" />
</logic:present>
<input type="hidden" name="wresult" value="<bean:write name="wresult" />" />
</div>
<noscript>
<div>
<input type="submit" value="Continue" />
</div>
</noscript>

</form>
</body>
</html>
