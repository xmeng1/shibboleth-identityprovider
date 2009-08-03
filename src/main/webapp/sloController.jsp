<%@page import="edu.internet2.middleware.shibboleth.idp.slo.SingleLogoutContext" %>
<%@page import="edu.internet2.middleware.shibboleth.idp.slo.SingleLogoutContextStorageHelper" %>
<%@page import="java.util.Locale" %>
<%
SingleLogoutContext sloContext = SingleLogoutContextStorageHelper.getSingleLogoutContext(request);
String contextPath = request.getContextPath();
Locale defaultLocale = Locale.ENGLISH;
Locale locale = request.getLocale();
if (locale == null) {
    locale = defaultLocale;
}
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

						if ((status=="LOGOUT_ATTEMPTED" || status=="LOGOUT_UNSUPPORTED") && timer > 15){
							src = "failed.png";
							succ = true;
							wasfail = true;
						}

                        document.getElementById(entity).src = "<%= contextPath %>/images/" + src;

                    }
                    if (succ == true) {
                        clearTimeout(timeout);
                        if (!wasfail) finish();
                    }
                }
            }

            function finish() {
				document.getElementById("result").style.display = "block";
                //window.parent.location = "<%= contextPath %>/SLOServlet?finish";
            }

            function tick() {
                timer += 1;
                if (timer % checkInterval == 0) {
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
            %>
            <div class="row"><%= service.getDisplayName(locale, defaultLocale) %><img id="<%= service.getEntityID() %>" src="<%= contextPath %>/images/indicator.gif"></div>
            <iframe src="<%= contextPath %>/SLOServlet?action&<%= i %>" width="0" height="0"></iframe>
            <%
            }
            %>
			<div class="result" id="result" style="display:none">You have successfully logged out</div>
        </div>
    </body>
</html>