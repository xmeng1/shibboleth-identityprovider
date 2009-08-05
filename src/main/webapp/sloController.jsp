<%@page import="edu.internet2.middleware.shibboleth.idp.slo.SingleLogoutContext" %>
<%@page import="edu.internet2.middleware.shibboleth.idp.slo.SingleLogoutContextStorageHelper" %>
<%@page import="java.util.Locale" %>
<%@page import="java.net.URLEncoder" %>
<%@page import="java.io.UnsupportedEncodingException" %>
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
        <script language="javascript" type="text/javascript">
            var timer = 1;
            var timeout;
            var wasFailed = false;
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

                        if ((status=="LOGOUT_ATTEMPTED" || status=="LOGOUT_UNSUPPORTED") && timer >= 8){
                            src = "failed.png";
                            wasFailed = true;
                            succ=true;
                        }

                        document.getElementById(entity).src = "<%= contextPath %>/images/" + src;

                    }
                    if (succ==true || timer >= 8) finish(wasFailed);

                }
            }

            function finish(wasFailed) {
                
                var str = "You have successfully logged out";
                var className = "success";
                if (wasFailed){
                    str = "Problem. We ask you to close your browser to log out" ;
                    className = "fail";
                }
                document.getElementById("result").className = className;
                document.getElementById("result").innerHTML = str;
                document.getElementById("result").innerHTML += '<form action="<%= contextPath %>/SLOServlet" style="padding-top:10px;width:90%;clear:both;"><input type="hidden" name="finish" /><input type="submit" value="Back to the application" /></form><div class="clear"></div>';
                clearTimeout(timeout);

            }

            function tick() {
                timer += 1;
                if (timer  == 1 || timer  == 2 || timer  == 4 || timer  == 8) {
                    checkStatus();
                }

                timeout = setTimeout(tick, 1000);
            }
        </script>
    </head>
    <body onload="javascript: tick();">
        <div class="content">
            <h1>Logging out</h1>
            <%
            int i = 0;
            for (SingleLogoutContext.LogoutInformation service : sloContext.getServiceInformation().values()) {
                i++;
                String entityID = null;
                try {
                    entityID = URLEncoder.encode(service.getEntityID(), "UTF-8");
                } catch (UnsupportedEncodingException ex) {
                    throw new RuntimeException(ex);
                }
                StringBuilder src = new StringBuilder(contextPath);
                src.append("/images/");
                switch (service.getLogoutStatus()) {
                    case LOGGED_IN:
                    case LOGOUT_ATTEMPTED:
                        src.append("indicator.gif");
                        break;
                    case LOGOUT_UNSUPPORTED:
                    case LOGOUT_FAILED:
                        src.append("failed.png");
                        break;
                    case LOGOUT_SUCCEEDED:
                        src.append("success.png");
                        break;
                }
            %>
            <div class="row">
                <%= service.getDisplayName(locale, defaultLocale) %>
                <img alt="<%= service.getLogoutStatus().toString() %>" id="<%= service.getEntityID() %>" src="<%= src.toString() %>">
            </div>
            <%
            if (service.isLoggedIn()) {
                //if-logged-in
            %>
            <iframe src="<%= contextPath %>/SLOServlet?action&entityID=<%= entityID %>" width="0" height="0"></iframe>
            <%
            } //end of if-logged-in
            } //end of for-each-service
            %>
            <div id="result"></div>
        </div>
    </body>
</html>