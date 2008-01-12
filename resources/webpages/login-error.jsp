<%@page import="edu.internet2.middleware.shibboleth.common.profile.AbstractErrorHandler"%>

<%
  Throwable error = (Throwable) request.getAttribute(AbstractErrorHandler.ERROR_KEY);
%>

<html>

<body>
	<img src="<%= request.getContextPath() %>/images/logo.jpg" />
	<h3>ERROR</h3>
	Error Message: <%= error.getMessage() %>
	
</body>

</html>