<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html 
        PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" 
        "DTD/xhtml1-strict.dtd">
	<%@ page import="edu.internet2.middleware.shibboleth.aa.*" %>
	<%@ page import="javax.naming.*" %>
	<%@ page import="javax.naming.directory.*" %>
	<%@ page import="java.util.*" %>
        <%@ taglib uri="/WEB-INF/tlds/struts-logic.tld" prefix="logic" %>
        <%@ taglib uri="/WEB-INF/tlds/struts-bean.tld" prefix="bean" %>
        <jsp:useBean id="requestURL" scope="request" class="java.lang.String"/>
        <jsp:useBean id="username" scope="request" class="java.lang.String"/>
	<jsp:useBean id="userCtx" scope="request" class="javax.naming.directory.DirContext"/>
	<jsp:useBean id="attr" scope="request" class="edu.internet2.middleware.shibboleth.aa.ArpAttribute"/>
	<jsp:useBean id="userAttr" scope="request" class="edu.internet2.middleware.shibboleth.aa.ArpAttribute"/>
	<jsp:useBean id="resource" scope="request" class="java.lang.String"/>
	<jsp:useBean id="close" scope="request" class="java.lang.String"/>
	<jsp:useBean id="adminArp" scope="request" class="edu.internet2.middleware.shibboleth.aa.Arp"/>
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
  <head>
        <link rel="stylesheet" type="text/css" href="main.css" />
        <title>Shibboleth ARP</title>

  </head>

<body
<% 
 if (close.equals("true")) 
	out.println(" onLoad=window.close()");
%>
>
	
    <p><b>Editing filter for attribute <bean:write name="attr" /></b></p>
    
     Select values for this attribute that should <b>not</b> be released:

    <p><form name="filter_form" action="<bean:write name="requestURL" />" method="POST">
	<table>
	
<% 
    Set s = getReleaseSet(adminArp, resource, resource, adminArp);
    ArpAttribute adminAttr = getAttr(s, attr);
    ArpFilter filter = combineFilters(userAttr.getFilter(), 
 				      adminAttr.getFilter());

    Attribute dAttr = attr.getDirAttribute(userCtx, true);

    if (dAttr != null && dAttr.size() > 0) {
    for (int j=0; j < dAttr.size(); j++)  {
      String checked = "";
      if (filter != null) {
	ArpFilterValue afv = new ArpFilterValue(dAttr.get(j), false);
	ArpFilterValue[] afva = filter.getFilterValues();	
	for (int k=0;k<afva.length;k++) { 
	  if (afva[k].equals(afv))  
	    checked = "checked";
	}
      }

      out.println("<tr><td>"+dAttr.get(j)+"</td>");
      out.println("<td><input type=\"checkbox\" name=\"filterval\" value=\""+dAttr.get(j)+"\" "+checked+">&nbsp;Yes</td></tr>");
    } 
  }
%>

	</table>
      <p>
      <input type=hidden name="Attr" value="<jsp:getProperty name="attr" property="name"/>">
      <input type=hidden name="username" value="<bean:write name="username"/>">
      <input type=hidden name="Resource" value="<bean:write name="resource"/>"> 
      <input type=submit name="Submit" value="Save Filter">
      <input type=submit name="Submit" value="Cancel" onClick="javascript:window.close();">
  </form>
  

