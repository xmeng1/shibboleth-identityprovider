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

<p>
This is an example of a page protected by the Shibboleth system. The
Apache server hosting this page contains the following configuration
block in its httpd.conf file:
<blockquote>
<pre>&lt;Location /shibboleth-target/sample.jsp&gt;
AuthType shibboleth
ShibRequireSession On
require valid-user
&lt;/Location&gt;</pre>
</blockquote>
</p>

<p>Because of the "require valid-user" rule, any user from a trusted
origin-site is allowed access, once they establish a session using
Shibboleth.</p>

<p>Here are some pieces of information I can tell about you using
the information Shibboleth gives me:<p>

<p>
<ul>
<% if (request.getRemoteUser()!=null) { %>
    <li>Your eduPersonPrincipalName is: <b><%= request.getRemoteUser() %></b></li>
<% } %>
<% if (request.getHeader("Shib-EP-Affiliation")!=null) { %>
    <li>Your eduPersonScopedAffiliation value(s):
    <b><%= request.getHeader("Shib-EP-Affiliation") %></b></li>
<% } %>
<% if (request.getHeader("Shib-EP-Entitlement")!=null) { %>
    <li>Your eduPersonEntitlement value(s):
    <b><%= request.getHeader("Shib-EP-Entitlement") %></b></li>
<% } %>
<% if (request.getHeader("Shib-PersistentID")!=null) { %>
    <li>Your PersistentID value(s):
    <b><%= request.getHeader("Shib-PersistentID") %></b></li>
<% } %>
</ul>
</p>

</body>
</html>
