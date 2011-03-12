<%@ page import="edu.internet2.middleware.shibboleth.idp.authn.LoginContext" %>
<%@ page import="edu.internet2.middleware.shibboleth.idp.authn.LoginHandler" %>
<%@ page import="edu.internet2.middleware.shibboleth.idp.session.*" %>
<%@ page import="edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper" %>
<%@ page import="org.opensaml.saml2.metadata.*" %>

<%@ taglib uri="/mdui" prefix="mdui" %>


<%
    LoginContext loginContext = HttpServletHelper.getLoginContext(HttpServletHelper.getStorageService(application),
                                                                  application, request);
    Session userSession = HttpServletHelper.getUserSession(request);
%>

<html>

    <head>
        <title>Shibboleth Identity Provider - Example Login Page</title>
    </head>
	<body>

        <img src="<%= request.getContextPath()%>/images/logo.jpg" />
		<h1>Example Login Page</h1>
		<p>This login page is an example and should be customized.  Refer to the 
			<a href="https://spaces.internet2.edu/display/SHIB2/IdPAuthUserPassLoginPage" target="_new"> documentation</a>.
		</p>
		
		<div style="border: 2px solid;padding: 4px">
		  The Following information is made available via the &lt;mdui:taglibs&gt; It is included purely as
          an example.

            <p>
                Service Name = <mdui:serviceName/>
            </p>

            <p>
                The service description: is <mdui:serviceDescription>not present</mdui:serviceDescription>
            </p>
                
            <p>
                Support text could read:  If you don't know why you got here please contact <mdui:serviceContact cssClass="claz1">your support desk</mdui:serviceContact>
            </p>

            <p>
                <mdui:servicePrivacyURL cssId="id2" linkText="The PS Privacy Statement">No Privacy Statement</mdui:servicePrivacyURL>
            </p>
            
            <p>
                <mdui:serviceInformationURL cssStyle="font-style:Italic" linkText="More Information">No Information URL</mdui:serviceInformationURL>
            </p>

            <mdui:serviceLogo cssId="logoId" cssClass="class" minWidth="20" maxHeight="400">No logo available</mdui:serviceLogo>
        </div>
    

		<% if (loginContext == null) { %>
		<p><font color="red">Error:</font> Direct access to this page is not supported.</p>
		<% } else { %>		
		
			<h2>Shibboleth Identity Provider Login to Service Provider <%= loginContext.getRelyingPartyId() %></h2>
					
			<% if (request.getAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY) != null) { %>
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
		<%}%>
	</body>
	
</html>