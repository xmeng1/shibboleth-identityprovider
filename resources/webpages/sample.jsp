<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html 
	PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" 
	"DTD/xhtml1-strict.dtd">
	<%@ taglib uri="/WEB-INF/tlds/struts-logic.tld" prefix="logic" %>
	<%@ taglib uri="/WEB-INF/tlds/struts-bean.tld" prefix="bean" %>
	
	<jsp:useBean id="logoLocation" scope="application" class="java.lang.String"/>
	
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
	<link rel="stylesheet" type="text/css" href="main.css" />
	<title>Shibboleth Protected Page</title>
</head>

<body>
<div class="head">
<img src="<bean:write name="logoLocation" />" alt="Logo" />
<h1>Shibboleth Inter-institutional Access Control System</h1>
</div>

<p>This is an example of a page protected by the Shibboleth system.</p>

<p>Because of the "require valid-user" rule, any user from a trusted
Identity Provider is allowed access, once they establish a session using
Shibboleth.</p>

<p>Here are some pieces of information I can tell about you using
the information Shibboleth gives me:<p>

<p>
<ul>
<%
String h = null;
java.util.Enumeration headers = request.getHeaderNames();
while (headers != null && headers.hasMoreElements()) {
        h = (String)headers.nextElement();
        if (!h.equals("Shib-Attributes") && !h.equals("Shib-Application-ID") && ((h.startsWith("Shib-") || h.equalsIgnoreCase("remote_user")))) {
%>
                <li><%= h %> is: <b><%= request.getHeader(h) %></b></li>
<%
        }
%>
<% } %>
</ul>
</p>

<p>The raw SAML attribute assertion I received is below. If it makes sense to
you, seek medical attention immediately.</p>
<%
String encoded=request.getHeader("Shib-Attributes");
String a = "";
if (encoded != null && !encoded.equals("")) {
        byte[] decoded=org.apache.xml.security.utils.Base64.decode(encoded.getBytes());
        a = new String(decoded);
}
%>

<textarea wrap="soft" rows="20" cols="80"><%= a %></textarea>

</body>
</html>
