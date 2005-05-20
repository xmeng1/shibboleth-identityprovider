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

/**
 * Simple Servlet Filter that strips realm information from Kerberos authenticated container-managed security
 * 
 * @author Scott Cantor
 */
public class KerberosPrincipalFilter implements Filter {

	private static Logger log = Logger.getLogger(KerberosPrincipalFilter.class.getName());

	/**
	 * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
	 */
	public void init(FilterConfig config) throws ServletException {

	}

	/**
	 * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse,
	 *      javax.servlet.FilterChain)
	 */
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
			ServletException {

		if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
			MDC.put("serviceId", "[Kerberos Principal Filter]");
			log.error("Only HTTP(s) requests are supported by the KerberosPrincipalFilter.");
			return;
		}
		HttpServletRequest httpRequest = (HttpServletRequest) request;

		String name = httpRequest.getRemoteUser();
		int split = name.indexOf('@');
		if (split > -1) name = name.substring(0, split);

		chain.doFilter(new KerberosPrincipalWrapper(httpRequest, new PrincipalImpl(name)), response);
	}

	/**
	 * @see javax.servlet.Filter#destroy()
	 */
	public void destroy() {

	}

	class KerberosPrincipalWrapper extends HttpServletRequestWrapper {

		Principal principal;

		KerberosPrincipalWrapper(HttpServletRequest request, Principal principal) {

			super(request);
			this.principal = principal;
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

	class PrincipalImpl implements Principal {

		private String name = null;

		PrincipalImpl(String name) {

			this.name = name;
		}

		/**
		 * @see java.security.Principal#getName()
		 */
		public String getName() {

			return name;
		}

		/**
		 * @see java.lang.Object#equals(java.lang.Object)
		 */
		public boolean equals(Object obj) {

			return name.equals(obj);
		}

		/**
		 * @see java.lang.Object#toString()
		 */
		public String toString() {

			return name;
		}

	}
}
