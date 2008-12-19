<%@page import="edu.internet2.middleware.shibboleth.common.profile.AbstractErrorHandler"%>

<html>

<body>
	<img src="<%= request.getContextPath() %>/images/logo.jpg" />
	<h3>ERROR</h3>
	<p>
	    An error occurred while processing your request.  Please contact your helpdesk or
	    user ID office for assistance.
	</p>
	<p>
	   This service requires cookies.  Please ensure that they are enabled and try your 
	   going back to your desired resource and trying to login again.
	</p>
	<p>
	   Use of your browser's back button may cause specific errors that can be resolved by
	   going back to your desired resource and trying to login again.
	</p>
	<% 
       Throwable error = (Throwable) request.getAttribute(AbstractErrorHandler.ERROR_KEY);
	   if(error != null){
	%>
	<strong>Error Message: <%= error.getMessage() %></strong>
	<% } %>
	
</body>

</html>