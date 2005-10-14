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
package edu.internet2.middleware.shibboleth.utils;

import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.mockrunner.mock.web.MockHttpServletRequest;
import com.mockrunner.mock.web.MockHttpServletResponse;

/**
 * Assorted convenience methods for working with MockRunner
 * 
 * @author Will Norris (wnorris@memphis.edu)
 */
public class MockObjectUtils {

	/**
	 * Set the client SSL certificate for the given request object
	 * 
	 * @param request
	 * @param certFile
	 *            path to client SSL certificate
	 * @throws Exception
	 */
	public static void setClientCert(MockHttpServletRequest request,
			String certFile) throws Exception {
		FileInputStream fis = new FileInputStream(certFile);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		Collection c = cf.generateCertificates(fis);

		X509Certificate[] certs = new X509Certificate[c.size()];
		certs = (X509Certificate[]) c.toArray(certs);

		request.setAttribute("javax.servlet.request.X509Certificate", certs);
	}

	/**
	 * Get SAML status message from the given response object
	 * 
	 * @param response
	 * @return
	 */
	public static String getSamlStatusMessage(MockHttpServletResponse response) {
		Pattern p = Pattern.compile("<StatusMessage>([^<]*)</StatusMessage>");
		Matcher m = p.matcher(response.getOutputStreamContent());
		if (m.find()) {
			return m.group(1);
		} else {
			return null;
		}
	}
}
