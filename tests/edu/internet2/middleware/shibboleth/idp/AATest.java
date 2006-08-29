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

import edu.internet2.middleware.shibboleth.utils.FileUtils;
import edu.internet2.middleware.shibboleth.utils.MockObjectUtils;

/**
 * MockObject unit tests for Shibboleth IdP Attribute Authority component
 * 
 * @author Will Norris (wnorris@memphis.edu)
 */
public class AATest extends IdpTestCase {

	/**
	 * Initialize request object with default client SSL certificate
	 * 
	 * @param requestFilename
	 *            path to file containing HTTP body for request
	 * @throws Exception
	 */
	private void initRequest(String requestFilename) throws Exception {

		initRequest(requestFilename, "data/idp/blackbox/sp.crt");
	}

	/**
	 * Initialize request object with given client SSL certificate
	 * 
	 * @param requestFilename
	 *            path to file containing HTTP body for request
	 * @param certFilename
	 *            path to file containing client SSL certificate
	 * @throws Exception
	 */
	private void initRequest(String requestFilename, String certFilename) throws Exception {

		File requestFile = new File(requestFilename);

		request.setRemoteAddr("127.0.0.1");
		request.setContextPath("/shibboleth-idp");
		request.setProtocol("HTTP/1.1");
		request.setScheme("https");
		request.setServerName("idp.example.org");
		request.setServerPort(443);

		request.setMethod("POST");
		request.setRequestURL("https://idp.example.org/shibboleth-idp/AA");
		request.setRequestURI("https://idp.example.org/shibboleth-idp/AA");
		request.setContentType("text/xml");
		request.setHeader("SOAPAction", "http://www.oasis-open.org/committees/security");
		request.setContentLength(new Long(requestFile.length()).intValue());

		request.setBodyContent(FileUtils.readFileToString(requestFile, "utf-8"));
		MockObjectUtils.setClientCert(request, certFilename);
	}

	/**
	 * Basic working Attribute Query
	 * 
	 * @throws Exception
	 */
	public void testBasicAttrQuery() throws Exception {

		resetServlet("data/idp/blackbox/conf/standard");
		initRequest("data/idp/blackbox/aa/request01.txt");

		testModule.doPost();

		assertTrue(responsesAreEqual(FileUtils.readFileToString(new File("data/idp/blackbox/aa/response01.txt"),
				"utf-8"), response.getOutputStreamContent()));
	}

	/**
	 * Attribute Query with invalid client credentials
	 * 
	 * @throws Exception
	 */
	public void testAttrQueryWithInvalidCred() throws Exception {

		resetServlet("data/idp/blackbox/conf/standard");
		initRequest("data/idp/blackbox/aa/request01.txt", "data/idp/blackbox/sp-bad.crt");

		testModule.doPost();

		assertEquals("Invalid credentials for request.", MockObjectUtils.getSamlStatusMessage(response));
	}

	/**
	 * Attribute Query with default relying party
	 * 
	 * @throws Exception
	 */
	public void testAttrQueryWithDefaultRelyingParty() throws Exception {

		resetServlet("data/idp/blackbox/conf/SPRelyingParty");
		initRequest("data/idp/blackbox/aa/request01.txt");

		testModule.doPost();

		assertTrue(responsesAreEqual(FileUtils.readFileToString(new File("data/idp/blackbox/aa/response01.txt"),
				"utf-8"), response.getOutputStreamContent()));
	}

	/**
	 * Attribute Query with SP matched relying party
	 * 
	 * @throws Exception
	 */
	public void testAttrQueryWithSpMatchedRelyingParty() throws Exception {

		resetServlet("data/idp/blackbox/conf/SPRelyingParty");
		initRequest("data/idp/blackbox/aa/request03.txt");

		testModule.doPost();

		assertTrue(responsesAreEqual(FileUtils.readFileToString(new File("data/idp/blackbox/aa/response03.txt"),
				"utf-8"), response.getOutputStreamContent()));
	}

	/**
	 * Attribute Query with group matched relying party
	 * 
	 * @throws Exception
	 */
	public void testAttrQueryWithGroupMatchedRelyingParty() throws Exception {

		resetServlet("data/idp/blackbox/conf/groupRelyingParty");
		initRequest("data/idp/blackbox/aa/request04.txt");

		testModule.doPost();

		assertTrue(responsesAreEqual(FileUtils.readFileToString(new File("data/idp/blackbox/aa/response04.txt"),
				"utf-8"), response.getOutputStreamContent()));
	}

	/**
	 * Attribute Query with error pass thru
	 * 
	 * @throws Exception
	 */
	public void testAttrQueryWithErrorPassThru() throws Exception {

		resetServlet("data/idp/blackbox/conf/passThruErrors");
		initRequest("data/idp/blackbox/aa/request05.txt");

		testModule.doPost();

		assertEquals("General error processing request. (wrapped: Name Identifier format not registered.)",
				MockObjectUtils.getSamlStatusMessage(response));
	}

	/**
	 * Attribute Query with attribute designators. Instead of the IdP returning all attributes allowed for the
	 * requesting SP, the SP specifies specifically which attributes it wants.
	 * 
	 * @throws Exception
	 */
	public void testAttrQueryWithAttrDesignators() throws Exception {

		resetServlet("data/idp/blackbox/conf/standard");
		initRequest("data/idp/blackbox/aa/request06.txt");

		testModule.doPost();

		assertTrue(responsesAreEqual(FileUtils.readFileToString(new File("data/idp/blackbox/aa/response06.txt"),
				"utf-8"), response.getOutputStreamContent()));
	}

	/**
	 * Attribute Query with unknown name identifier type
	 * 
	 * @throws Exception
	 */
	public void testAttrQueryWithUnknownNameIdentifierType() throws Exception {

		resetServlet("data/idp/blackbox/conf/standard");
		initRequest("data/idp/blackbox/aa/request05.txt");

		testModule.doPost();

		assertEquals("General error processing request.", MockObjectUtils.getSamlStatusMessage(response));
	}

	/**
	 * Attribute Query with incorrect name identifier
	 * 
	 * @throws Exception
	 */
	public void testAttrQueryWithIncorrectNameIdentifier() throws Exception {

		resetServlet("data/idp/blackbox/conf/groupRelyingParty");
		initRequest("data/idp/blackbox/aa/request07.txt");

		testModule.doPost();

		assertEquals("General error processing request.", MockObjectUtils.getSamlStatusMessage(response));
	}

	/**
	 * Attribute Query with signed assertions
	 * 
	 * @throws Exception
	 */
	public void testAttrQueryWithSignedAssertions() throws Exception {

		resetServlet("data/idp/blackbox/conf/signAssertions");
		initRequest("data/idp/blackbox/aa/request01.txt");

		testModule.doPost();

		assertTrue(responsesAreEqual(FileUtils.readFileToString(new File("data/idp/blackbox/aa/response08.txt"),
				"utf-8"), response.getOutputStreamContent()));
	}

	/**
	 * Attribute Query with ARP constraint
	 * 
	 * @throws Exception
	 */
	public void testAttrQueryWithConstraint() throws Exception {

		resetServlet("data/idp/blackbox/conf/constraints");
		initRequest("data/idp/blackbox/aa/request01.txt");

		testModule.doPost();

		assertTrue(responsesAreEqual(FileUtils.readFileToString(new File("data/idp/blackbox/aa/response09.txt"),
				"utf-8"), response.getOutputStreamContent()));
	}

	/**
	 * Attribute Query with attribute designators and ARP constraint
	 * 
	 * @throws Exception
	 */
	public void testAttrQueryWithDesignatorsAndConstraint() throws Exception {

		resetServlet("data/idp/blackbox/conf/constraints");
		initRequest("data/idp/blackbox/aa/request06.txt");

		testModule.doPost();

		assertTrue(responsesAreEqual(FileUtils.readFileToString(new File("data/idp/blackbox/aa/response06.txt"),
				"utf-8"), response.getOutputStreamContent()));
	}

}
