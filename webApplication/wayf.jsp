<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" 
	"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
<%@ taglib uri="/WEB-INF/tlds/struts-logic.tld" prefix="logic" %>
	<%@ taglib uri="/WEB-INF/tlds/struts-bean.tld" prefix="bean" %>
	<jsp:useBean id="requestURL" scope="request" class="java.lang.String"/>
	<jsp:useBean id="helpText" scope="application" class="java.lang.String"/>
	<jsp:useBean id="supportContact" scope="application" class="java.lang.String"/>
	<jsp:useBean id="shire" scope="request" class="java.lang.String"/>
	<jsp:useBean id="target" scope="request" class="java.lang.String"/>
	<jsp:useBean id="encodedShire" scope="request" class="java.lang.String"/>
	<jsp:useBean id="encodedTarget" scope="request" class="java.lang.String"/>
	<jsp:useBean id="searchResultEmptyText" scope="application" class="java.lang.String"/>
	<jsp:useBean id="logoLocation" scope="application" class="java.lang.String"/>
	<logic:present name="searchresults" scope="request">
		<jsp:useBean id="searchresults" scope="request" type="edu.internet2.middleware.shibboleth.wayf.Origin[]"/>
	</logic:present>
<head>
		<link rel="stylesheet" title="normal" type="text/css" href="wayf.css" /><title>InCommon: Identity Provider Selection</title></head>
	<body>

		<div class="head">
			<h1>Select an identity provider</h1>
		</div>

		<div class="selector">
			<p class="text"><bean:write name="helpText" /></p>

			<div class="list">

				<h2>Choose from a list:</h2>
				<logic:iterate id="originset" name="originsets">
				<form method="get" action="<bean:write name="requestURL" />">
					<p>
					<input type="hidden" name="shire" value="<bean:write name="shire" />" />
					<input type="hidden" name="target" value="<bean:write name="target" />" />
					<input type="hidden" name="action" value="selection" />
					<select name="origin">	
						<logic:iterate id="origin" name="originset" property="origins">
							<option value="<jsp:getProperty name="origin" property="name" />">
								<jsp:getProperty name="origin" property="displayName" />
							</option>
						</logic:iterate>
					</select>
						<input type="submit" value="Select" />
						<input type="checkbox" checked="checked" name="cache" value="TRUE" /><span class="warning">Remember my selection on this computer.</span>
						</p>
					</form>
					</logic:iterate>

				</div>
				<div class="search">
				<span class="option">or</span>
				<h2>Search by keyword:</h2>

					<form method="get" action="<bean:write name="requestURL" />">
						<p>
							<input type="hidden" name="shire" value="<bean:write name="shire" />" />
							<input type="hidden" name="target" value="<bean:write name="target" />" />
							<input type="hidden" name="action" value="search" />
							<input type="text" name="string" />
							<input type="submit" value="Search" />
						</p>
					</form>
					<logic:present name="searchResultsEmpty" scope="request">
						<p class="error"><bean:write name="searchResultEmptyText" /></p>
					</logic:present>
					<logic:present name="searchresults" scope="request">
						<h3>Search results:</h3>
						<form method="get" action="<bean:write name="requestURL" />">
							<ul>
							<logic:iterate id="currResult" name="searchresults">
								<li>
								<input type="radio" name="origin" value="<jsp:getProperty name="currResult" property="name" />" /><jsp:getProperty name="currResult" property="displayName" />
								</li>
							</logic:iterate>
							</ul>
							<p>
								<input type="hidden" name="shire" value="<bean:write name="shire" />" />
								<input type="hidden" name="target" value="<bean:write name="target" />" />
								<input type="hidden" name="action" value="selection" />
								<input type="submit" value="Select" />
								<input type="checkbox" checked="checked" name="cache" value="TRUE" /><span class="warning">Remember my selection on this computer.</span>
							</p>
						</form>	
					</logic:present>

				</div>
			</div>
			<div class="footer">

				<p class="text">Need assistance? Send mail to <a href="mailto:shib-test@internet2.edu">shib-test@internet2.edu</a> with description.</p>
				<div class="logo"><img src="./images/incommon.gif" alt="InCommon" /></div>
			</div>
			
	</body></html>
