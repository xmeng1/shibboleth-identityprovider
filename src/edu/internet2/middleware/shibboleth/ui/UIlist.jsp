<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html 
        PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" 
        "DTD/xhtml1-strict.dtd">
	<%@ page import="edu.internet2.middleware.shibboleth.aa.*" %>
	<%@ page import="javax.naming.*" %>
	<%@ page import="javax.naming.directory.*" %>
	<%@ page import="org.opensaml.*" %>
        <%@ taglib uri="/WEB-INF/tlds/struts-logic.tld" prefix="logic" %>
        <%@ taglib uri="/WEB-INF/tlds/struts-bean.tld" prefix="bean" %>
        <jsp:useBean id="requestURL" scope="request" class="java.lang.String"/>
        <jsp:useBean id="username" scope="request" class="java.lang.String"/>
	<jsp:useBean id="shars" scope="request" class="edu.internet2.middleware.shibboleth.aa.ArpShar[]"/>
	<jsp:useBean id="debug" scope="request" class="java.lang.String"/>
	<jsp:useBean id="responder" scope="request" class="edu.internet2.middleware.shibboleth.aa.AAResponder"/>

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
  <head>
        <link rel="stylesheet" type="text/css" href="main.css" />
        <title>Shibboleth ARP</title>
  </head>


  <body>
    <div class="head">
      <h1>Shibboleth Attribute Release Policy</h1>
    </div>

    <p><b>ARP for <bean:write name="username" /></b></p>

<% if (shars.length > 0) { 
%>
    <table width="100%" border=1>
	<tr>
	  <th width="20%">Resource Name</th>
	  <th width="20%">Notes</th> 
	  <th width="30%">Attributes Released</th>
	  <th>Actions</th>
	</tr>
<logic:iterate id="shar" name="shars">
  <logic:iterate id="resource" name="shar" property="resources">
    <tr>
<%
    String sharname = ((edu.internet2.middleware.shibboleth.aa.ArpShar)shar).getName();
    String res = ((edu.internet2.middleware.shibboleth.aa.ArpResource)resource).getName();
    String resourceUrl = (res.startsWith("http")) ? 
	resourceUrl = res.substring(res.indexOf(":")+3) : res;
%>
    <form name="list<jsp:getProperty name="resource" property="name" />" action="<bean:write name="requestURL"/>" method="post">
	<td><a href="http://<%=resourceUrl%>"><jsp:getProperty name="resource" property="name" /></a></td>
	<td><jsp:getProperty name="resource" property="comment" /></td>
	<td>
<%
  SAMLAttribute[] attrSet = responder.getReleaseAttributes(
		username, "uid=", "", 	
		sharname, res );

  for (int j=0; j<attrSet.length; j++) {
    Object[] vals = attrSet[j].getValues();
    for (int k=0; k<vals.length; k++) {
      out.println(vals[k] + "<br>");
    }
  }
%>
	</td>
	<input type=hidden name="username" value="<bean:write name="username"/>">
	<input type=hidden name="Resource" value="<jsp:getProperty name="resource" property="name"/>">
	    <td><input type="submit" name="Submit" value="Delete">&nbsp;
	<input type="submit" name="Submit" value="Edit">&nbsp;
	<input type="submit" name="Submit" value="Copy"></td>
	</form>
    </tr>
  </logic:iterate>
</logic:iterate>
    </table>
<% }%>    
    <p>
    <form name="act" action="<bean:write name="requestURL" />" method="post">
    <input type=hidden name="username" value="<bean:write name="username"/>">
    <input type=submit name="Submit" value="Add new resource"</a><br>
    <input type=submit name="Submit" value="Delete all ARPs"</a><br>
<%  if (debug == "true") %>
    <input type=submit name="Submit" value="Change user"</a><br>

    </form>
    </p>

  </body>
</html>

