/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package edu.internet2.middleware.shibboleth.idp;

import java.io.File;

import org.apache.commons.codec.binary.Base64;

import edu.internet2.middleware.shibboleth.utils.FileUtils;

/**
 * MockObject unit tests for Shibboleth IdP Single Sign On component
 * 
 * @author Will Norris (wnorris@memphis.edu)
 */
public class SSOTest extends IdpTestCase {

	/**
	 * Initialize SSO request object
	 */
	private void initRequest() {
		request.setRemoteAddr("127.0.0.1");
		request.setContextPath("/shibboleth-idp");
		request.setProtocol("HTTP/1.1");
		request.setScheme("https");
		request.setServerName("idp.example.org");
		request.setServerPort(443);

		request.setMethod("GET");
		request.setRequestURL("https://idp.example.org/shibboleth-idp/SSO");
		request.setRequestURI("https://idp.example.org/shibboleth-idp/SSO");
	}

	/**
	 * Basic working SSO flow using Artifact
	 * 
	 * @throws Exception
	 */
	public void testBasicSsoArtifactFlow() throws Exception {
		resetServlet("data/idp/blackbox/conf/standard");

		initRequest();
		request.setupAddParameter("target",
				"https://sp.example.org/cgi-bin/login.cgi");
		request.setupAddParameter("shire",
				"https://sp.example.org/Shibboleth.sso/SAML/Artifact");
		request.setupAddParameter("providerId", "urn:x-shibtest:SP");
		request.setRemoteUser("gpburdell");

		testModule.doGet();

		assertTrue(response
				.getHeader("Location")
				.matches(
						"https://sp.example.org/Shibboleth.sso/SAML/Artifact?.*"
								+ "TARGET=https%3A%2F%2Fsp.example.org%2Fcgi-bin%2Flogin.cgi"
								+ "&SAMLart=[^&]+" + "&SAMLart=[^&]+"));
	}

	/**
	 * Basic working SSO flow using POST
	 * 
	 * @throws Exception
	 */
	public void testBasicSsoPostFlow() throws Exception {
		resetServlet("data/idp/blackbox/conf/ssoPost");

		initRequest();
		request.setupAddParameter("target",
				"https://sp.example.org/cgi-bin/login.cgi");
		request.setupAddParameter("shire",
				"https://sp.example.org/Shibboleth.sso/SAML/POST");
		request.setupAddParameter("providerId", "urn:x-shibtest:SP");
		request.setRemoteUser("gpburdell");

		testModule.doGet();

		String bin64assertion = (String) request.getAttribute("assertion");
		String assertion = new String(Base64.decodeBase64(bin64assertion
				.getBytes()));

		assertTrue(responsesAreEqual(FileUtils.readFileToString(new File(
				"data/idp/blackbox/sso/response01.txt"), "utf-8"), assertion));
	}

	/**
	 * Basic working 1.1 SSO flow
	 * 
	 * @throws Exception
	 */
	public void testBasic11SsoFlow() throws Exception {
		resetServlet("data/idp/blackbox/conf/standard");

		initRequest();
		request.setupAddParameter("target",
				"https://sp.example.org/cgi-bin/login.cgi");
		request.setupAddParameter("shire",
				"https://sp.example.org/Shibboleth.shire");
		request.setRemoteUser("gpburdell");

		testModule.doGet();

		String bin64assertion = (String) request.getAttribute("assertion");
		String assertion = new String(Base64.decodeBase64(bin64assertion
				.getBytes()));

		assertTrue(responsesAreEqual(FileUtils.readFileToString(new File(
				"data/idp/blackbox/sso/response02.txt"), "utf-8"), assertion));
	}

	/**
	 * SSO flow with invalid SP Acceptance URL
	 * 
	 * @throws Exception
	 */
	public void testSsoFlowWithInvalidSpAcceptanceUrl() throws Exception {
		resetServlet("data/idp/blackbox/conf/standard");

		initRequest();
		request.setupAddParameter("target",
				"https://sp.example.org/cgi-bin/login.cgi");
		request.setupAddParameter("shire",
				"https://invalid.edu/Shibboleth.sso/SAML/Artifact");
		request.setupAddParameter("providerId", "urn:x-shibtest:SP");
		request.setRemoteUser("gpburdell");

		testModule.doGet();

		assertEquals(
				"org.opensaml.SAMLException: Invalid assertion consumer service URL.",
				request.getAttribute("errorText"));
	}

	/**
	 * SSO flow with signed assertions
	 * 
	 * @throws Exception
	 */
	public void testSsoFlowWithSignedAssertions() throws Exception {
		resetServlet("data/idp/blackbox/conf/signAssertions");

		initRequest();
		request.setupAddParameter("target",
				"https://sp.example.org/cgi-bin/login.cgi");
		request.setupAddParameter("shire",
				"https://sp.example.org/Shibboleth.sso/SAML/POST");
		request.setupAddParameter("providerId", "urn:x-shibtest:SP");
		request.setRemoteUser("gpburdell");

		testModule.doGet();

		String bin64assertion = (String) request.getAttribute("assertion");
		String assertion = new String(Base64.decodeBase64(bin64assertion
				.getBytes()));

		assertTrue(responsesAreEqual(FileUtils.readFileToString(new File(
				"data/idp/blackbox/sso/response03.txt"), "utf-8"), assertion));
	}

}
