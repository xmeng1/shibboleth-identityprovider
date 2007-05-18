/*
 * Copyright [2006] [University Corporation for Advanced Internet Development, Inc.]
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

package edu.internet2.middleware.shibboleth.idp.authn.provider;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationHandler;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;

/**
 * {@link AuthenticationHandler} that redirects to servlet protected by a Web
 * Single-Sign-On system.
 */
public class RemoteUserAuthenticationHandler implements AuthenticationHandler {

	private static final Logger log = Logger
			.getLogger(RemoteUserAuthenticationHandler.class);

	/** The URI of the AuthnContextDeclRef or the AuthnContextClass. */
	private String authnMethodURI;

	/** The duration of the authNContext. */
	private long authnDuration;

	/** The URL of the SSO-protected servlet. */
	private String servletURL;

	private boolean supportsPassive = false;

	private boolean supportsForce = false;

	/** Creates a new instance of RemoteUserAuthenticationHandler */
	public RemoteUserAuthenticationHandler() {
	}

	public void setSupportsPassive(boolean supportsPassive) {
		this.supportsPassive = supportsPassive;
	}

	public void setSupportsForce(boolean supportsForce) {
		this.supportsForce = supportsForce;
	}

	public boolean supportsPassive() {
		return supportsPassive;
	}

	public boolean supportsForceAuthentication() {
		return supportsForce;
	}

	/**
	 * Set the duration of the AuthnContext.
	 * 
	 * @param duration
	 *            The duration of the AuthnContext.
	 */
	public void setAuthnDuration(long duration) {
		authnDuration = duration;
	}

	/**
	 * Return the duration of the AuthnContext.
	 * 
	 * @return the duration of the AuthnContext.
	 */
	public long getAuthnDuration() {
		return authnDuration;
	}

	/**
	 * Set the SSO-protected servlet's URL.
	 * 
	 * @param servletURL
	 *            The URL of the SSO-protected servlet.
	 */
	public void setServletURL(String servletURL) {
		this.servletURL = servletURL;
	}

	/**
	 * Get the URL of the SSO-protected servlet.
	 * 
	 * @return The URL of the SSO-protected servlet.
	 */
	public String getServletURL() {
		return servletURL;
	}

	/** @{inheritDoc} */
	public void login(final HttpServletRequest request,
			final HttpServletResponse response, final LoginContext loginCtx) {

		// set some initial values.
		loginCtx.setAuthenticationAttempted();
		loginCtx.setAuthenticationMethod(authnMethodURI);
		loginCtx.setAuthenticationDuration(authnDuration);

		// forward control to the servlet.
		try {
			RequestDispatcher dispatcher = request
					.getRequestDispatcher(servletURL);
			dispatcher.forward(request, response);
		} catch (IOException ex) {
			log
					.error(
							"RemoteUserAuthenticationHandler: Unable to forward control to SSO servlet.",
							ex);
		} catch (ServletException ex) {
			log
					.error(
							"RemoteUserAuthenticationHandler: Unable to forward control to SSO servlet.",
							ex);
		}

	}

	/** @{inheritDoc} */
	public void logout(final HttpServletRequest request,
			final HttpServletResponse response, String principal) {

	}

}
