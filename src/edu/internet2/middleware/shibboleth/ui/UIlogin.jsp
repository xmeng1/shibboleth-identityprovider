<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html 
        PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" 
        "DTD/xhtml1-strict.dtd">
        <%@ taglib uri="/WEB-INF/tlds/struts-logic.tld" prefix="logic" %>
        <%@ taglib uri="/WEB-INF/tlds/struts-bean.tld" prefix="bean" %>
        <jsp:useBean id="requestURL" scope="request" class="java.lang.String"/>
        <jsp:useBean id="username" scope="request" class="java.lang.String"/>
        <jsp:useBean id="err" scope="request" class="java.lang.String"/>
        <jsp:useBean id="debug" scope="request" class="java.lang.String"/>

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
  <head>
        <link rel="stylesheet" type="text/css" href="main.css" />
        <title>Shibboleth Attribute Release Policy Login</title>
  </head>

  <body>
    <div class="head">
      <h1>Shibboleth Attribute Release Policy Login</h1>
    </div>

    <b><bean:write name="err" /></b>
    <p><b>Not logged in</b></p>

<% if (debug == "true")  { %>
    <form action="<bean:write name="requestURL" />" method="post">
      <p>Editing Attribute Release Policy for user 
        <input type = "text" size="10" name="username" value="<bean:write name="username" />" /> &nbsp;&nbsp;&nbsp;
        <input type="submit" name="Submit" value="Login" />
      </p>
    </form>
<%}%>
  </body>
</html>