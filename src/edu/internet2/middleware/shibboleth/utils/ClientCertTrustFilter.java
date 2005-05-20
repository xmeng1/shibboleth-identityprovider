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

import java.io.IOException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.apache.log4j.MDC;

import edu.internet2.middleware.shibboleth.common.LocalPrincipal;

/**
 * Simple Servlet Filter that populates the ServletRequest with data from a client certificate. Relies on external
 * mechanisms to properly authorize the certificate.
 * 
 * @author Walter Hoehn
 */
public class ClientCertTrustFilter implements Filter {

	private static Logger log = Logger.getLogger(ClientCertTrustFilter.class.getName());
	protected Pattern regex = Pattern.compile(".*CN=([^,/]+).*");
	protected int matchGroup = 1;

	/**
	 * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
	 */
	public void init(FilterConfig config) throws ServletException {

		if (config.getInitParameter("regex") != null) {
			try {
				regex = Pattern.compile(config.getInitParameter("regex"));
			} catch (PatternSyntaxException e) {
				throw new ServletException(
						"Failed to start ClientCertTrustFilter: supplied regular expression fails to compile.");
			}
		}

		if (config.getInitParameter("matchGroup") != null) {
			try {
				matchGroup = Integer.parseInt(config.getInitParameter("matchGroup"));
			} catch (NumberFormatException e) {
				throw new ServletException(
						"Failed to start ClientCertTrustFilter: supplied matchGroup is not an integer.");
			}
		}
	}

	/**
	 * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse,
	 *      javax.servlet.FilterChain)
	 */
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
			ServletException {

		MDC.put("serviceId", "[Client Cert Trust Filter]");

		if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
			log.error("Only HTTP(s) requests are supported by the ClientCertTrustFilter.");
			return;
		}
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;

		log.debug("Using regex: (" + regex.pattern() + ").");
		log.debug("Using matchGroup of (" + matchGroup + ")");

		X509Certificate[] certs = (X509Certificate[]) httpRequest.getAttribute("javax.servlet.request.X509Certificate");
		if (certs == null) {
			log.error("Processed a request that did not contain a client certificate.");
			httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Client certificate required.");
			return;
		}

		log.debug("Attempting to extract principal name from Subjet: (" + certs[0].getSubjectDN().getName() + ").");
		Matcher matches = regex.matcher(certs[0].getSubjectDN().getName());
		if (!matches.find()) {
			log.error("Principal could not be extracted from Certificate Subject.");
			httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN,
					"Client certificate does not contain required data.");
			return;
		}
		String principalName;
		try {
			principalName = matches.group(matchGroup);
		} catch (IndexOutOfBoundsException e) {
			log.error("Principal could not be extracted from Certificate Subject: matchGroup out of bounds.");
			httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN,
					"Client certificate does not contain required data.");
			return;
		}
		log.debug("Extracted principal name (" + principalName + ") from Subject.");
		chain.doFilter(new ClientCertTrustWrapper(httpRequest, new LocalPrincipal(principalName)), response);
	}

	/**
	 * @see javax.servlet.Filter#destroy()
	 */
	public void destroy() {

	// required by interface
	// no resources to clean
	}

	/**
	 * <code>HttpServletRequest</code> wrapper class. Returns a locally specified principal and hardcoded authType.
	 */
	private class ClientCertTrustWrapper extends HttpServletRequestWrapper {

		private Principal principal;

		private ClientCertTrustWrapper(HttpServletRequest request, Principal principal) {

			super(request);
			this.principal = principal;
		}

		/**
		 * @see javax.servlet.http.HttpServletRequest#getAuthType()
		 */
		public String getAuthType() {

			return HttpServletRequest.CLIENT_CERT_AUTH;
		}

		/**
		 * @see javax.servlet.http.HttpServletRequest#getRemoteUser()
		 */
		public String getRemoteUser() {

			return principal.getName();
		}

		/**
		 * @see javax.servlet.http.HttpServletRequest#getUserPrincipal()
		 */
		public Principal getUserPrincipal() {

			return principal;
		}
	}

}