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

package edu.internet2.middleware.shibboleth.idp.authn.impl;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

import java.util.concurrent.CopyOnWriteArrayList;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.ServletRequest;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationHandler;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;

import org.apache.log4j.Logger;

import org.joda.time.DateTime;

/**
 * IP Address authentication handler.
 * 
 * This "authenticates" a user based on their IP address. It operates in either
 * default deny or default allow mode, and evaluates a given request against a
 * list of blocked or permitted IPs. It supports both IPv4 and IPv6.
 */
public class IPAddressHandler implements AuthenticationHandler {

	private static final Logger log = Logger.getLogger(IPAddressHandler.class
			.getName());

	/** the URI of the AuthnContextDeclRef or the AuthnContextClass */
	private String authnMethodURI;

	/** The return location */
	private String returnLocation;

	/** Are the IPs in ipList a permitted list or a deny list */
	private boolean defaultDeny;

	/** The list of denied or permitted IPs */
	private List<InetAddress> ipList;

	/** Creates a new instance of IPAddressHandler */
	public IPAddressHandler() {
	}

	/**
	 * Set the permitted IP addresses.
	 * 
	 * If <code>defaultDeny</code> is <code>true</code> then only the IP
	 * addresses in <code>ipList</code> will be "authenticated." If
	 * <code>defaultDeny</code> is <code>false</code>, then all IP
	 * addresses except those in <code>ipList</code> will be authenticated.
	 * 
	 * @param ipList
	 *            A list of {@link InetAddress}es.
	 * @param defaultDeny
	 *            Does <code>ipList</code> contain a deny or permit list.
	 */
	public void setIpList(final List<InetAddress> ipList, boolean defaultDeny) {

		this.ipList = new CopyOnWriteArrayList(ipList);
		this.defaultDeny = defaultDeny;
	}

	/** {@inheritDoc  */
	public void setReturnLocation(String location) {
		this.returnLocation = location;
	}

	/** @{inheritDoc} */
	public boolean supportsPassive() {
		return (true);
	}

	/** {@inheritDoc} */
	public boolean supportsForceAuthentication() {
		return (true);
	}

	/** {@inheritDoc} */
	public void logout(HttpServletRequest request,
			HttpServletResponse response, String principal) {

		RequestDispatcher dispatcher = request
				.getRequestDispatcher(this.returnLocation);
		dispatcher.forward(request, response);
	}

	/** {@inheritDoc} */
	public void login(HttpServletRequest request, HttpServletResponse response,
			boolean passive, boolean force) {

		HttpSession httpSession = request.getSession();
		if (httpSession == null) {
			log.error("Unable to retrieve HttpSession from request.");
			return;
		}
		Object o = httpSession.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
		if (!(o instanceof LoginContext)) {
			log
					.error("Invalid login context object -- object is not an instance of LoginContext.");
			return;
		}
		LoginContext loginContext = (LoginContext) o;

		loginContext.setAuthenticationAttempted();
		loginContext.setAuthenticationInstant(new DateTime());

		if (this.defaultDeny) {
			this.handleDefaultDeny(request, response, loginContext);
		} else {
			this.handleDefaultAllow(request, response, loginContext);
		}

	}

	private void handleDefaultDeny(HttpServletRequest request,
			HttpServletResponse response, LoginContext loginCtx) {

		boolean ipAllowed = this.searchIpList(request);

		if (ipAllowed) {
			loginCtx.setAuthenticationOK(true);
		} else {
			loginCtx.setAuthenticationOK(false);
			loginCtx
					.setAuthenticationFailureMessage("User's IP is not in the permitted list.");
		}
	}

	private void handleDefaultAllow(HttpServletRequest request,
			HttpServletResponse response, LoginContext loginCtx) {

		boolean ipDenied = this.searchIpList(request);

		if (ipDenied) {
			loginCtx.setAuthenticationOK(false);
			loginCtx
					.setAuthenticationFailureMessage("Users's IP is in the deny list.");
		} else {
			loginCtx.setAuthenticationOK(true);
		}
	}

	/**
	 * Search the list of InetAddresses for the client's address.
	 * 
	 * @param request
	 *            The ServletReqeust
	 * 
	 * @return <code>true</code> if the client's address is in
	 *         <code>this.ipList</code>
	 */
	private boolean searchIpList(final ServletRequest request) {

		boolean found = false;

		try {
			InetAddress[] addrs = InetAddress.getAllByName(request
					.getRemoteAddr());
			for (InetAddress a : addrs) {
				if (this.ipList.contains(a)) {
					found = true;
					break;
				}
			}
		} catch (UnknownHostException ex) {
			log.error("Error resolving hostname: ", ex);
		}

		return (found);
	}

}
