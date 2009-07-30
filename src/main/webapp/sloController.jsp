<%@page import="edu.internet2.middleware.shibboleth.idp.slo.SingleLogoutContext" %>
<%@page import="edu.internet2.middleware.shibboleth.idp.slo.SingleLogoutContextStorageHelper" %>
<%
SingleLogoutContext sloContext = SingleLogoutContextStorageHelper.getSingleLogoutContext(request);
String contextPath = request.getContextPath();
%>
<html>
    <head>
        <link title="style" href="<%= contextPath %>/css/main.css" type="text/css" rel="stylesheet" />
        <title>Shibboleth IdP Frontchannel Single Log-out Controller</title>
        <script language="javascript" type="text/javascript">
            var timer = 1;
            var checkInterval = 5;
            
            var xhr = new XMLHttpRequest();
            xhr.onreadystatechange = updateStatus;

            function checkStatus() {
                xhr.open("GET", "<%= contextPath %>/SLOServlet?status", true);
                xhr.send(null);
            }

            function updateStatus() {
                if (xhr.readyState == 4 && xhr.status == 200) {
                    var resp = eval("(" + xhr.responseText + ")");
                    succ = true;
                    for (var service in resp) {
                        var entity = resp[service].entityID;
                        var status = resp[service].logoutStatus;
                        var src = "indicator.gif";

                        switch(status) {
                            case "LOGOUT_SUCCEEDED" : src="success.png";
                                break;
                            case "LOGOUT_FAILED" : src="failed.png";
                                break;
                            case "LOGOUT_ATTEMPTED" : src="indicator.gif";
                                break;
                        }

                        if (status != 'LOGOUT_SUCCEEDED') {
                            succ = false;
                        }
                        document.getElementById(entity).src = "<%= contextPath %>/images/" + src;
                    }
                    if (succ == true) {
                        alert('Logout successful');
                        finish();
                    }
                }
            }

            function finish() {
                window.parent.location = "<%= contextPath %>/SLOServlet?finish";
            }

            function tick() {
                //document.getElementById("timer").innerHTML = timer;
                timer += 1;
                if (timer % checkInterval == 0) {
                    checkStatus();
                }
                setTimeout(tick, 1000);
            }
        </script>
    </head>
    <body onload="javascript: tick();">
        <!--<span id="timer">0</span> <a href="#" onclick="javascript:checkStatus();">checkStatus</a><br/>-->
        <div class="content">
            <h1>Logging out</h1>
            <%
            for (SingleLogoutContext.LogoutInformation service : sloContext.getServiceInformation().values()) {
            %>
            <div class="row"><%= service.getEntityID() %><img id="<%= service.getEntityID() %>" src="<%= contextPath %>/images/indicator.gif"></div>
            <iframe src="<%= contextPath %>/SLOServlet?action" width="0" height="0" style="position:absolute;top:-1000px;"></iframe>
            <%
            }
            %>
        </div>
    </body>
</html>