<%@page import="edu.internet2.middleware.shibboleth.idp.slo.SingleLogoutContext" %>
<%@page import="edu.internet2.middleware.shibboleth.idp.slo.SingleLogoutContextStorageHelper" %>
<%
SingleLogoutContext sloContext = SingleLogoutContextStorageHelper.getSingleLogoutContext(request);
int spCnt = sloContext.getServiceInformation().values().size();
StringBuilder b = new StringBuilder();
for (int i = 0; i < spCnt - 1; i++) {
    b.append("*,");
}
b.append("*");
%>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN"
   "http://www.w3.org/TR/html4/frameset.dtd">
<html>
    <head>
        <title>Shibboleth IdP Frontchannel Single Log-out Controller</title>
    </head>
    <frameset cols="1, *">
        <frameset rows="<%= b.toString() %>">
            <%
            for (int i = 0; i < spCnt; i++) {
            %>
            <frame src="/idp/SLOServlet?action" />
            <% }  %>
        </frameset>
        <frame src="/idp/SLOServlet?statusFrame" />
    </frameset>
</html>
