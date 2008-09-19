<html>

    <head>
        <title>Shibboleth Identity Provider - Login</title>
    </head>

	<body>
		<img src="<%= request.getContextPath() %>/images/logo.jpg" />
		<h2>Shibboleth Identity Provider Login</h2>
		
		<% if ("true".equals(request.getAttribute("loginFailed"))) { %>
		<p><font color="red"Authentication Failed</font></p>
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
				<td rowspan="2"><input type="submit" value="Login" tabindex="3" /></td>
			</tr>
		</table>
		</form>
	</body>
	
</html>