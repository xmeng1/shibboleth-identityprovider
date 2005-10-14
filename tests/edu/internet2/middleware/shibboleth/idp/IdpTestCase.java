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
import java.io.FileNotFoundException;
import java.io.IOException;

import junit.framework.TestCase;

import com.mockrunner.mock.web.MockFilterConfig;
import com.mockrunner.mock.web.MockHttpServletRequest;
import com.mockrunner.mock.web.MockHttpServletResponse;
import com.mockrunner.mock.web.MockServletContext;
import com.mockrunner.mock.web.WebMockObjectFactory;
import com.mockrunner.servlet.ServletTestModule;

import edu.internet2.middleware.shibboleth.utils.FileUtils;

/**
 * Base class for Shibboleth IdP MockObject unit tests.
 * 
 * @author Will Norris (wnorris@memphis.edu)
 */
public abstract class IdpTestCase extends TestCase {

	// The Factory creates the Request, Response, Session, etc.
	WebMockObjectFactory factory = new WebMockObjectFactory();

	// The TestModule runs the Servlet and Filter methods in the simulated
	// container
	ServletTestModule testModule = new ServletTestModule(factory);

	// Now simulated Servlet API objects
	MockServletContext servletContext = factory.getMockServletContext();

	MockFilterConfig filterConfig = factory.getMockFilterConfig();

	MockHttpServletResponse response = factory.getMockResponse();

	MockHttpServletRequest request = factory.getMockRequest();

	protected void setUp() throws Exception {
		super.setUp();

		// ServletContext (argument to Filters and Servlets)
		servletContext.setServletContextName("Shibboleth Test Context");
		servletContext.setInitParameter("IdPConfigFile", new File(tmpIdpHome()
				+ "/etc/idp.xml").toURL().toString());
		// testModule.setServlet(sso);
	}

	/**
	 * Start the IdP servlet using the given config directory and reset request
	 * and response objects
	 * 
	 * @param configDir
	 *            this directory will be copied to IDP_HOME/etc
	 * @throws IOException
	 */
	void resetServlet(String configDir) throws IOException {
		// setup config directory and initialize servlet
		prepareConfigDir(new File(configDir));
		IdPConfigLoader.reset();
		testModule.createServlet(IdPResponder.class);

		// reset request and response objects
		request.clearAttributes();
		request.clearParameters();
		response.reset();
	}

	/**
	 * Copy configDir to IDP_HOME/etc. Any instances of the string "$IDP_HOME$"
	 * in the file idp.xml will be replaced with the current IdP home directory
	 * 
	 * @param configDir
	 * @throws IOException
	 */
	private void prepareConfigDir(File configDir) throws IOException {
		try {
			FileUtils.forceDelete(new File(tmpIdpHome() + "/etc"));
		} catch (FileNotFoundException fnf) {
			// directory doesn't exist... no big deal
		}

		FileUtils.copyDirectory(configDir, new File(tmpIdpHome() + "/etc"));
		new File(tmpIdpHome() + "/logs").mkdir();

		FileUtils.replaceString(new File(tmpIdpHome() + "/etc/idp.xml"),
				"\\$IDP_HOME\\$", new File(tmpIdpHome()).toURL().toString());
	}

	/**
	 * Get a temporary directory to be used as IDP_HOME during testing.
	 * 
	 * @return
	 */
	private String tmpIdpHome() {
		// TODO: ideally this should check for a TMP environment variable, or at
		// least return a platform appropriate directory. Fortunately, /tmp is
		// properly converted to C:\tmp in Windows,
		// so the following should still work across platforms
		return "/tmp/shibboleth-idp";
	}

	/**
	 * Test two SAML response bodies for equality. Because many items in a SAML
	 * response are generated at runtime (such as ResponseID, IssueInstant,
	 * etc), an exact string match is not possible. To handle this, the expected
	 * string should be a regular expression which will be used to match against
	 * the received string. Any extra whitespace and any whitespace between XML
	 * tags will be ignored.
	 * 
	 * @param expected
	 *            regular expression used to match against the received string
	 * @param received
	 *            HTTP body of received response
	 * @return
	 */
	boolean responsesAreEqual(String expected, String received) {
		// ignore extra whitespace
		String exp = expected.replaceAll("\\s+", " ");
		String rec = received.replaceAll("\\s+", " ");

		// ignore whitespace between tags
		exp = exp.replaceAll("\\s*(>|<)\\s*", "$1");
		rec = rec.replaceAll("\\s*(>|<)\\s*", "$1");

		// System.out.println("exp = " + exp);
		// System.out.println("rec = " + rec);

		return rec.matches(exp);
	}

}
