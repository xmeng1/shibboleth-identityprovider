<%@page import="edu.internet2.middleware.shibboleth.idp.slo.SingleLogoutContext" %>
<%@page import="edu.internet2.middleware.shibboleth.idp.slo.SingleLogoutContextStorageHelper" %>
<%@page import="java.util.Locale" %>
<%
SingleLogoutContext sloContext = SingleLogoutContextStorageHelper.getSingleLogoutContext(request);
String contextPath = request.getContextPath();
Locale defaultLocale = Locale.ENGLISH;
Locale locale = request.getLocale();
%>
<html>
    <head>
        <link title="style" href="<%= contextPath %>/css/main.css" type="text/css" rel="stylesheet" />
        <title>Shibboleth IdP Frontchannel Single Log-out Controller</title>
    </head>
    <body>
        <div class="content">
            <h1>Logging out</h1>
			<h2>You are logged in on these services</h2>
            <%
            int i = 0;
            for (SingleLogoutContext.LogoutInformation service : sloContext.getServiceInformation().values()) {
                i++;
            %>
            <div class="row"><%= service.getDisplayName(locale, defaultLocale) %></div>
            <%
            }
            %>
			<div class="controller">Do you want to logout from all the services above?<br />
				<input type="button" onclick="javascript:document.location='<%= contextPath %>/SLOServlet?logout';" value="Yes, all services" />
				<input type="button" onclick="javascript:document.location='<%= contextPath %>/SLOServlet?finish';" value="No, it was a mistake, go back" /><br />
			</div>
        </div>
    </body>
</html>