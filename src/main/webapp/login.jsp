<%@ taglib uri="/mdui" prefix="mdui" %>
<html>
  <link rel="stylesheet" type="text/css" href="<%= request.getContextPath()%>/login.css"/>
  <head>
    <title>Shibboleth Identity Provider - Example Login Page</title>
  </head>

  <body id="homepage">
    <img src="<%= request.getContextPath()%>/images/logo.jpg" />
    <h1>Example Login Page</h1>
    <p>This login page is an example and should be customized.  Refer to the 
       <a href="https://spaces.internet2.edu/display/SHIB2/IdPAuthUserPassLoginPage" target="_blank"> documentation</a>.
    </p>

    <div class="loginbox">
       <div class="leftpane">
         <div class="content">
           <p>The web site described to the right has asked you to log in and you have chosen &lt;FILL IN YOUR SITE&gt; as your home institution</p>
           <% if ("true".equals(request.getAttribute("loginFailed"))) { %>
              <p><font color="red"> Credentials not recognized. </font> </p>
           <% } %>
           <% if(request.getAttribute("actionUrl") != null){ %>
             <form action="<%=request.getAttribute("actionUrl")%>" method="post">
           <% }else{ %>
             <form action="j_security_check" method="post">
           <% } %>
           <table>
             <tr><td width="40%"><label for="username">Username:</label></td><td><input name="j_username" type="text" /></td></tr>
             <tr><td><label for="password">Password:</label></td><td><input name="j_password" type="password" /></td></tr>
             <tr><td></td><td><button type="submit" value="Login" >Continue</button></td></tr>
           </table></form>
         </div>
       </div>
       <div class="rightpane">
         <div class="content">
           <div id="spName"><mdui:serviceName/></div>
           <!-- pick the logo.  If its between 64 & max width/height display it
                If its too high but OK wide clip by height
                If its too wide clip by width.
                We should not clip by height and width since that skews the image.  Too high an image will just show the top.
            -->
           <mdui:serviceLogo  minWidth="64" minHeight="64" maxWidth="350" maxHeight="147" cssId="splogo">
              <mdui:serviceLogo  minWidth="64" minHeight="64" maxWidth="350" cssId="clippedsplogoY">
                  <mdui:serviceLogo  minWidth="64" minHeight="64" cssId="clippedsplogoX"/>
              </mdui:serviceLogo>
           </mdui:serviceLogo>
           <div id="spDescription">
             <mdui:serviceDescription>You have asked to login to <mdui:serviceName/></mdui:serviceDescription>
           </div>
         </div>
      </div>
    </div>
  </body>
</html>
