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
    ArpAttribute adminAttr = getAdminAttr(adminArp, resource, userAttr.getName());
    ArpFilter admFilter = adminAttr.getFilter();
    ArpFilter filter = userAttr.getFilter();

    Attribute dAttr = attr.getDirAttribute(userCtx, true);

    if (dAttr != null && dAttr.size() > 0) {
    for (int j=0; j < dAttr.size(); j++)  {
      String checked = "";
      if (filter != null) {
	ArpFilterValue afv = new ArpFilterValue(dAttr.get(j), false);
	ArpFilterValue afvt = new ArpFilterValue(dAttr.get(j), true);
	ArpFilterValue[] afva = filter.getFilterValues();
	if (filter.contains(afv)) {
	    checked = "<input type=\"checkbox\" name=\"filterval\" value=\""+dAttr.get(j)+"\" checked> Yes";
	} else {
	    checked = "<input type=\"checkbox\" name=\"filterval\" value=\""+dAttr.get(j)+"\"> Yes";
	}
	ArpFilterValue[] afvi = admFilter.getFilterValues();
	for (int k=0;k<afvi.length;k++) {
	    if (afvi[k].equals(afv) && (afvi[k].mustInclude() == false)) {
	        checked = "<i>filtered</i>";
 	    }
	    if (afvi[k].equals(afvt) && (afvi[k].mustInclude())) {
	        checked = "<i>released</i>";
 	    }
	}
      }

      out.println("<tr><td>"+dAttr.get(j)+"</td>");
      out.println("<td>"+checked+"</td></tr>");
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
  
<%!
public ArpAttribute getAdminAttr(Arp admin, 
			String resource, String attr) {
    ArpShar s = admin.getShar(resource);
    if (s == null) {
	s = admin.getDefaultShar();
    }
    if (s == null)
	return null;
    ArpResource r = s.bestFit(resource);
    if (r == null)
	return null;
    ArpAttribute a = r.getAttribute(attr);
    return a;
}

public ArpFilter combineFilters(ArpAttribute attr1, ArpAttribute attr2){
    ArpFilter filt2 = attr2.getFilter();
    if (attr1 == null) 
 	return filt2;
    ArpFilter filt1 = attr1.getFilter();
    if(filt1 == null)
	return filt2;

    if(filt2 == null)
	return filt1;

    ArpFilterValue[]  fv1Array = filt1.getFilterValues();
	
    for(int i=0; i<fv1Array.length; i++){
	ArpFilterValue afv = fv1Array[i];

        if(afv.mustInclude()){  // cannot be filtered out
	    filt2.removeFilterValue(afv); // ok if not there
	}else{
	    filt2.addAFilterValue(afv);
	}
    }
    return filt2;
}
    
    
%>	
  </body>	
</html>	  

