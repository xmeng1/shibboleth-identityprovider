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
	<jsp:useBean id="resource" scope="request" class="edu.internet2.middleware.shibboleth.aa.ArpResource"/>
	<jsp:useBean id="allAttrs" scope="request" class="java.lang.String[]"/>
	<jsp:useBean id="userCtx" scope="request" class="javax.naming.directory.DirContext"/>
	<jsp:useBean id="isNew" scope="request" class="java.lang.String"/>
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
  <head>
        <link rel="stylesheet" type="text/css" href="main.css" />
        <title>Shibboleth ARP</title>
<SCRIPT TYPE="text/javascript">
<!--
function popupFilter(attr) 
{
    res = window.document.edit.Resource.value;
    if (res.length == 0 || res.indexOf(" ") != -1) {
	alert("Please enter a valid resource URL"); 
    } else {
        var url = "<bean:write name="requestURL" />?Submit=Filter&username=<bean:write name="username"/>&Attr="+attr+"&Resource="+res;
        window.open(url, 'fpage', 'resizable, height=300, width=250, dependant=yes');
    }
    return false;
}

function formSubmit()
{
   res = window.document.edit.Resource.value;
   if (res.length == 0 || res.indexOf(" ") != -1) {
	alert("Please enter a valid resource URL");
        return false;
   }
   return true;
}
function formCancel()
{
   return true;
}
//-->
</SCRIPT>

  </head>


  <body>
    <div class="head">
      <h1>Shibboleth Attribute Release Policy</h1>
    </div>

    <p><b>Editing ARP for <bean:write name="username" /></b></p>

    <form name="edit" action="<bean:write name="requestURL" />" method="post">
    <input type=hidden name="username" value="<bean:write name="username"/>">
    <input type=hidden name="isNew" value="<bean:write name="isNew" />">
    <p><b>Resource URL:</b> 
<% 
    if (isNew.equals("true")) {
%>
      <input type=text name="Resource" size=30 value="<jsp:getProperty name="resource" property="name"/>"> 
<%   
    } else { 
%>
        <input type=hidden name="Resource" value="<jsp:getProperty name="resource" property="name"/>">
<%
	out.println(resource.getName());
    }
%>	

    </p><br>

    <b>Attribute Release Policy:</b>
    <hr>
    <table width="100%" border=0>
      <tr align="left">
	<th width="30%">Attribute</th>
	<th width="40%">All Value(s)</th>
	<th width="10%">Filter</th>
	<th width="10%">Release?</th>
      </tr>

<%
      for (int i=0; i<allAttrs.length; i++) {
	ArpAttribute aAttr = new ArpAttribute(allAttrs[i], false);
	Attribute dAttr = aAttr.getDirAttribute(userCtx, true);
	if (dAttr != null && dAttr.size() > 0) {
%>
          <tr><td>
	    <%=allAttrs[i]%>
	  </td>
	  <td>
<%
	  if (dAttr.size() > 1) {
	      out.println("<select name=\"values\" size=1>");
	      out.println("<option>[See Values]</option>");
	      for (int j=0; j < dAttr.size(); j++)  {
		out.println("<option>"+dAttr.get(j)+"</option>");
	      }
 	    out.println("</select>");
	  } else {
	      out.println(dAttr.get());
	  }

          String checkbool = "";
	  ArpAttribute a = null;
	  if (resource != null)
	    a = resource.getAttribute(allAttrs[i]);
	  if (a != null) 
 	    checkbool = "checked"; 
	  else
	    a = new ArpAttribute(allAttrs[i], false);

	  out.println("</td><td>");


	  if (dAttr.size() > 1) {
	  String filtStr="add";
	  if (a.hasFilter())
	     filtStr="edit";

%>

	 <a href="#" onClick="return popupFilter('<%=a.getName()%>','<%=resource.getName()%>');"><%=filtStr%></a>
<% } %>
	</td>
	<td>
	  <input type="checkbox" name="attr" value="<%=a.getName()%>" 
	  <%=checkbool%>>&nbsp;Yes
	</td>

      </tr>
<% } } %>
      </table>
      
      <p><b>Comment:</b>
	<br>
	<input type="text" name="comment" value="<jsp:getProperty name="resource" property="comment"/>" size="40">
	</textarea>
      </p>
	
      <hr>
	<input type="hidden" name="username" value="<bean:write name="username"/>">	
      <input type="submit" name="Submit" value="Save" onClick="return formSubmit();">&nbsp;&nbsp;

	<input type="submit" name="Submit" value="Cancel" onClick="return formCancel();" >
      </form>
    <hr>
	  
