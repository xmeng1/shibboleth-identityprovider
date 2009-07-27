<%@page import="edu.internet2.middleware.shibboleth.idp.slo.SingleLogoutContext" %>
<%@page import="edu.internet2.middleware.shibboleth.idp.slo.SingleLogoutContextStorageHelper" %>
<%
SingleLogoutContext sloContext = SingleLogoutContextStorageHelper.getSingleLogoutContext(request);
%>
<html>
    <head>
        <title>Shibboleth IdP Frontchannel Single Log-out Controller</title>
        <script language="javascript" type="text/javascript">
            var timer = 0;
            var checkInterval = 2;
            
            var xhr = new XMLHttpRequest();
            xhr.onreadystatechange = updateStatus;

            function checkStatus() {
                xhr.open("GET", "/idp/SLOServlet?status", true);
                xhr.send(null);
            }

            function updateStatus() {
                if (xhr.readyState == 4 && xhr.status == 200) {
                    var resp = eval("(" + xhr.responseText + ")");
                    succ = true;
                    for (var service in resp) {
                        var entity = resp[service].entityID;
                        var status = resp[service].logoutStatus;
                        if (status != 'LOGOUT_SUCCEEDED') {
                            succ = false;
                        }
                        document.getElementById(entity).innerHTML = status;
                    }
                    if (succ == true) {
                        window.parent.location = "/idp/SLOServlet?action";
                    }
                }
            }

            function tick() {
                document.getElementById("timer").innerHTML = timer;
                timer += 1;
                if (timer % checkInterval == 0) {
                    checkStatus();
                }
                setTimeout(tick, 1000);
            }
        </script>
    </head>
    <body onload="javascript: tick();">
        <span id="timer">0</span> <a href="#" onclick="javascript:checkStatus();">checkStatus</a><br/>
        <table>
            <%
            for (SingleLogoutContext.LogoutInformation service : sloContext.getServiceInformation().values()) {
            %>
            <tr>
                <td><%= service.getEntityID() %></td>
                <td id="<%= service.getEntityID() %>"><%= service.getLogoutStatus().toString()%></td>
            </tr>
            <%
            }
            %>
        </table>
    </body>
</html>