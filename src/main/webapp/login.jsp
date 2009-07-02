<%@ page import="edu.internet2.middleware.shibboleth.idp.authn.LoginContext" %>
<%@ page import="edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper" %>
<%@ page import="org.opensaml.saml2.metadata.*" %>

<%
   LoginContext loginContext = HttpServletHelper.getLoginContext(HttpServletHelper.getStorageService(application),
                                                                 application, request);
   EntityDescriptor entityDescriptor = HttpServletHelper.getRelyingPartyMetadata(loginContext.getRelyingPartyId(),
                                                   HttpServletHelper.getRelyingPartyConfirmationManager(application));  
%>

<html>

    <head>
        <title>Shibboleth Identity Provider - Login</title>
    </head>

	<body>
		<img src="<%= request.getContextPath() %>/images/logo.jpg" />
		<h2>Shibboleth Identity Provider Login to <%= entityDescriptor.getEntityID() %></h2>
		
		<% if ("true".equals(request.getAttribute("loginFailed"))) { %>
		<p><font color="red">Authentication Failed</font></p>
		<% } %>
		
		<% if(request.getAttribute("actionUrl") != null){ %>
		    <form action="<%=request.getAttribute("actionUrl")%>" method="post">
		<% }else{ %>
		    <form action="j_security_check" method="post">
		<% } %>
		<table>
			<tr>
				<td>Username:</td>
				<td><input name="j_username" type="text" tabindex="1" /></td>
			</tr>
			<tr>
				<td>Password:</td>
				<td><input name="j_password" type="password" tabindex="2" /></td>
			</tr>
			<tr>
				<td colspan="2"><input type="submit" value="Login" tabindex="3" /></td>
			</tr>
		</table>
		</form>
	</body>
	
</html>