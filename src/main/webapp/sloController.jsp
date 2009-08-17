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
Boolean logoutString = false;
Boolean sloFailed = false;
Boolean sloAttempted = false;
%>
<html>
    <head>
        <link title="style" href="<%= contextPath %>/css/main.css" type="text/css" rel="stylesheet" />
        <title>Shibboleth IdP Frontchannel Single Log-out Controller</title>
        <script language="javascript" type="text/javascript">
            <!--
            var timer = 0;
            var timeout;
            
            var xhr = new XMLHttpRequest();

            function checkStatus() {
                xhr.onreadystatechange = updateStatus;
                xhr.open("GET", "<%= contextPath %>/SLOServlet?status", true);
                xhr.send(null);
            }

            function updateStatus() {
                if (xhr.readyState != 4 || xhr.status != 200) {
                    return;
                }

                var sloFailed = false;
                var resp = eval("(" + xhr.responseText + ")");
                var ready = true;

                for (var service in resp) {
                    var entity = resp[service].entityID;
                    var status = resp[service].logoutStatus;
                    var src = "indicator.gif";
                    
                    switch(status) {
                        case "LOGOUT_SUCCEEDED" : 
                            src = "success.png";
                            break;
                        case "LOGOUT_FAILED" : 
                        case "LOGOUT_UNSUPPORTED" :
                            src = "failed.png";
                            sloFailed = true;
                            break;
                        case "LOGOUT_ATTEMPTED" : 
                        case "LOGGED_IN" :
                            if (timer >= 8) {
                                src = "failed.png";
                                sloFailed = true;
                                ready = true;
                            } else {
                                src = "indicator.gif";
                                ready = false;
                            }
                            break;
                    }
                    
                    document.getElementById(entity).src = "<%= contextPath %>/images/" + src;
                }

                if (ready) {
                    finish(sloFailed);
                }
            }

            function finish(sloFailed) {
                var str = "You have successfully logged out";
                var className = "success";
                if (sloFailed){
                    str = "Logout failed. Please exit from your browser to complete the logout process." ;
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

                timeout = setTimeout("tick()", 1000);
            }

            timeout = setTimeout("tick()", 1000);
            //-->
        </script>
    </head>
    <body>
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
                        logoutString = true;
                    case LOGOUT_ATTEMPTED:
                        sloAttempted = true;
                        src.append("indicator.gif");
                        break;
                    case LOGOUT_UNSUPPORTED:
                    case LOGOUT_FAILED:
                        sloFailed = true;
                        src.append("failed.png");
                        break;
                    case LOGOUT_SUCCEEDED:
                        logoutString = false;
                        src.append("success.png");
                        break;
                }
            %>
            <div class="row">
                <script type="text/javascript">
                    <!--
                    document.write('<%= service.getDisplayName(locale, defaultLocale) %><img alt="<%= service.getLogoutStatus().toString() %>" id="<%= service.getEntityID() %>" src="<%= src.toString() %>">');
                    //-->
                </script>
                <noscript><%= service.getDisplayName(locale, defaultLocale) %> <% if (logoutString) { %><a href="<%= contextPath %>/SLOServlet?action&entityID=<%= entityID %>" target="_blank">Logout from this SP</a> <% }  else { %><img alt="<%= service.getLogoutStatus().toString() %>" id="<%= service.getEntityID() %>" src="<%= src.toString() %>"><% } %></noscript>
            </div>
            <%
            if (service.isLoggedIn()) {
                //if-logged-in
            %>
            <script type="text/javascript">
                <!--
                document.write('<iframe src="<%= contextPath %>/SLOServlet?action&entityID=<%= entityID %>" width="0" height="0"></iframe>');
                //-->
            </script>
            <%
            } //end of if-logged-in
            } //end of for-each-service
            %>
            <div id="result"></div>
            <noscript>
                <p align="center">
                    <% if (logoutString || sloAttempted) { %>
                        <form action="<%= contextPath %>/SLOServlet" style="padding-top:10px;width:90%;clear:both;"><input type="hidden" name="logout" /><input type="submit" value="Refresh" /></form><div class="clear"></div>
                    <% } else { %>
                        <% if (sloFailed) { %>
                            <div id="result" class="fail">Logout failed. Please exit from your browser to complete the logout process.</div>
                        <% } else { %>
                            <div id="result" class="success">You have successfully logged out<form action="<%= contextPath %>/SLOServlet" style="padding-top:10px;width:90%;clear:both;"><input type="hidden" name="finish" /><input type="submit" value="Back to the application" /></form><div class="clear"></div></div>
                        <% }
                       } %>
                </p>
            </noscript>
        </div>
    </body>
</html>
