<%@page import="edu.internet2.middleware.shibboleth.idp.slo.SingleLogoutContext" %>
<%@page import="edu.internet2.middleware.shibboleth.idp.slo.SingleLogoutContextStorageHelper" %>
<%@page import="java.util.Locale" %>
<%
SingleLogoutContext sloContext = SingleLogoutContextStorageHelper.getSingleLogoutContext(request);
String contextPath = request.getContextPath();
Locale defaultLocale = Locale.ENGLISH;
Locale locale = request.getLocale();
String requesterSP = sloContext.getServiceInformation().
        get(sloContext.getRequesterEntityID()).getDisplayName(locale, defaultLocale);
%>
<html>
    <head>
        <link title="style" href="<%= contextPath %>/css/main.css" type="text/css" rel="stylesheet" />
        <title>Shibboleth IdP Frontchannel Single Log-out Controller</title>
    </head>
    <body>
        <div class="content">
            <h1>Logging out</h1>
            <h2>You have logged out from</h2>
            <div class="row"><%= requesterSP %></div>
			<h2>You are logged in on these services</h2>
            <%
            int i = 0;
            for (SingleLogoutContext.LogoutInformation service : sloContext.getServiceInformation().values()) {
                if (service.getEntityID().equals(sloContext.getRequesterEntityID())) {
                    continue;
                }
                i++;
            %>
            <div class="row"><%= service.getDisplayName(locale, defaultLocale) %></div>
            <%
            }
            %>
            <div class="controller">
                Do you want to logout from all the services above?<br />
                <form action="<%= contextPath %>/SLOServlet">
                    <input type="hidden" name="logout"/>
                    <input type="submit" value="Yes, all services" />
                </form>
                <form action="<%= contextPath %>/SLOServlet">
                    <input type="hidden" name="finish"/>
                    <input type="submit" value="No, only from <%= requesterSP %>" />
                </form>
                <div class="clear"></div>
            </div>
        </div>
    </body>
</html>