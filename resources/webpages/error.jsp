<%@page import="edu.internet2.middleware.shibboleth.common.profile.AbstractErrorHandler"%>

<%
  Throwable error = (Throwable) request.getAttribute(AbstractErrorHandler.ERROR_KEY);
%>

<html>

<body>
	<h1>ERROR</h1>
	Error Message: <%= error.getMessage() %>
	
</body>

</html>