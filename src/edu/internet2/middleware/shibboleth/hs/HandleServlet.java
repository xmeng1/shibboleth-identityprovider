/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved
 * 
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 * disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided with the distribution, if any, must include the
 * following acknowledgment: "This product includes software developed by the University Corporation for Advanced
 * Internet Development <http://www.ucaid.edu> Internet2 Project. Alternately, this acknowledegement may appear in the
 * software itself, if and wherever such third-party acknowledgments normally appear.
 * 
 * Neither the name of Shibboleth nor the names of its contributors, nor Internet2, nor the University Corporation for
 * Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote products derived from this software
 * without specific prior written permission. For written permission, please contact shibboleth@shibboleth.org
 * 
 * Products derived from this software may not be called Shibboleth, Internet2, UCAID, or the University Corporation
 * for Advanced Internet Development, nor may Shibboleth appear in their name, without prior written permission of the
 * University Corporation for Advanced Internet Development.
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE,
 * ACCURACY, AND EFFORT IS WITH LICENSEE. IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.hs;

import java.io.IOException;
import java.util.Collections;
import java.util.Date;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.doomdark.uuid.UUIDGenerator;
import org.opensaml.QName;
import org.opensaml.SAMLAuthorityBinding;
import org.opensaml.SAMLBinding;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
import org.opensaml.SAMLResponse;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import sun.misc.BASE64Decoder;
import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;
import edu.internet2.middleware.shibboleth.common.Credentials;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMapping;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMappingException;
import edu.internet2.middleware.shibboleth.common.OriginConfig;
import edu.internet2.middleware.shibboleth.common.ServiceProviderMapperException;
import edu.internet2.middleware.shibboleth.common.ShibPOSTProfile;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;

public class HandleServlet extends HttpServlet {

	private static Logger log = Logger.getLogger(HandleServlet.class.getName());
	private static Logger transactionLog = Logger.getLogger("Shibboleth-TRANSACTION");

	private Semaphore throttle;
	private HSConfig configuration;
	private Credentials credentials;
	private HSNameMapper nameMapper;
	private ShibPOSTProfile postProfile = new ShibPOSTProfile();
	private HSServiceProviderMapper targetMapper;

	protected void loadConfiguration() throws ShibbolethConfigurationException {

		Document originConfig = OriginConfig.getOriginConfig(this.getServletContext());

		//Load global configuration properties
		configuration = new HSConfig(originConfig.getDocumentElement());

		//Load signing credentials
		NodeList itemElements =
			originConfig.getDocumentElement().getElementsByTagNameNS(
				Credentials.credentialsNamespace,
				"Credentials");
		if (itemElements.getLength() < 1) {
			log.error("Credentials not specified.");
			throw new ShibbolethConfigurationException("The Handle Service requires that signing credentials be supplied in the <Credentials> configuration element.");
		}

		if (itemElements.getLength() > 1) {
			log.error("Multiple Credentials specifications found, using first.");
		}

		credentials = new Credentials((Element) itemElements.item(0));

		//Load name mappings
		itemElements =
			originConfig.getDocumentElement().getElementsByTagNameNS(
				NameIdentifierMapping.mappingNamespace,
				"NameMapping");

		for (int i = 0; i < itemElements.getLength(); i++) {
			try {
				nameMapper.addNameMapping((Element) itemElements.item(i));
			} catch (NameIdentifierMappingException e) {
				log.error("Name Identifier mapping could not be loaded: " + e);
			}
		}

		//Load relying party config
		try {
			targetMapper =
				new HSServiceProviderMapper(
					originConfig.getDocumentElement(),
					configuration,
					credentials,
					nameMapper);
		} catch (ServiceProviderMapperException e) {
			log.error("Could not load origin configuration: " + e);
			throw new ShibbolethConfigurationException("Could not load origin configuration.");
		}

	}

	public void init() throws ServletException {
		super.init();
		MDC.put("serviceId", "[HS] Core");
		transactionLog.setLevel((Level) Level.INFO);
		try {
			log.info("Initializing Handle Service.");

			nameMapper = new HSNameMapper();
			loadConfiguration();

			throttle = new Semaphore(configuration.getMaxThreads());

			log.info("Handle Service initialization complete.");

		} catch (ShibbolethConfigurationException ex) {
			log.fatal("Handle Service runtime configuration error.  Please fix and re-initialize. Cause: " + ex);
			throw new UnavailableException("Handle Service failed to initialize.");
		}
	}

	public void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {

		MDC.put("serviceId", "[HS] " + UUIDGenerator.getInstance().generateRandomBasedUUID());
		MDC.put("remoteAddr", req.getRemoteAddr());
		log.info("Handling request.");

		try {
			throttle.enter();
			checkRequestParams(req);

			req.setAttribute("shire", req.getParameter("shire"));
			req.setAttribute("target", req.getParameter("target"));

			HSRelyingParty relyingParty = targetMapper.getRelyingParty(req.getParameter("providerId"));

			String username =
				configuration.getAuthHeaderName().equalsIgnoreCase("REMOTE_USER")
					? req.getRemoteUser()
					: req.getHeader(configuration.getAuthHeaderName());

			SAMLNameIdentifier nameId =
				nameMapper.getNameIdentifierName(
					relyingParty.getHSNameFormatId(),
					new AuthNPrincipal(username),
					relyingParty,
					relyingParty.getIdentityProvider());

			String authenticationMethod = req.getHeader("SAMLAuthenticationMethod");
			if (authenticationMethod == null || authenticationMethod.equals("")) {
				authenticationMethod = relyingParty.getDefaultAuthMethod().toString();
				log.debug(
					"User was authenticated via the default method for this relying party ("
						+ authenticationMethod
						+ ").");
			} else {
				log.debug("User was authenticated via the method (" + authenticationMethod + ").");
			}

			byte[] buf =
				generateAssertion(
					relyingParty,
					nameId,
					req.getParameter("shire"),
					req.getRemoteAddr(),
					authenticationMethod);

			createForm(req, res, buf);

			transactionLog.info(
				"Authentication assertion issued to SHIRE ("
					+ req.getParameter("shire")
					+ ") providerId ("
					+ req.getParameter("providerId")
					+ ") on behalf of principal ("
					+ username
					+ ") for resource ("
					+ req.getParameter("target")
					+ "). Name Identifier: ("
					+ nameId.getName()
					+ "). Name Identifier Format: ("
					+ nameId.getFormat()
					+ ").");

		} catch (NameIdentifierMappingException ex) {
			log.error(ex);
			handleError(req, res, ex);
			return;
		} catch (InvalidClientDataException ex) {
			log.error(ex);
			handleError(req, res, ex);
			return;
		} catch (SAMLException ex) {
			log.error(ex);
			handleError(req, res, ex);
			return;
		} catch (InterruptedException ex) {
			log.error(ex);
			handleError(req, res, ex);
			return;
		} finally {
			throttle.exit();
		}
	}
	
	public void destroy() {
		log.info("Cleaning up resources.");
		nameMapper.destroy();
	}

	protected byte[] generateAssertion(
		HSRelyingParty relyingParty,
		SAMLNameIdentifier nameId,
		String shireURL,
		String clientAddress,
		String authType)
		throws SAMLException, IOException {

		SAMLAuthorityBinding binding =
			new SAMLAuthorityBinding(
				SAMLBinding.SAML_SOAP_HTTPS,
				relyingParty.getAAUrl().toString(),
				new QName(org.opensaml.XML.SAMLP_NS, "AttributeQuery"));

		SAMLResponse r =
			postProfile.prepare(
				shireURL,
				relyingParty,
				nameId,
				clientAddress,
				authType,
				new Date(System.currentTimeMillis()),
				Collections.singleton(binding));

		return r.toBase64();
	}

	protected void createForm(HttpServletRequest req, HttpServletResponse res, byte[] buf)
		throws IOException, ServletException {

		//Hardcoded to ASCII to ensure Base64 encoding compatibility
		req.setAttribute("assertion", new String(buf, "ASCII"));

		if (log.isDebugEnabled()) {
			try {
				log.debug(
					"Dumping generated SAML Response:"
						+ System.getProperty("line.separator")
						+ new String(new BASE64Decoder().decodeBuffer(new String(buf, "ASCII")), "UTF8"));
			} catch (IOException e) {
				log.error("Encountered an error while decoding SAMLReponse for logging purposes.");
			}
		}

		RequestDispatcher rd = req.getRequestDispatcher("/hs.jsp");
		rd.forward(req, res);
	}

	protected void handleError(HttpServletRequest req, HttpServletResponse res, Exception e)
		throws ServletException, IOException {

		req.setAttribute("errorText", e.toString());
		req.setAttribute("requestURL", req.getRequestURI().toString());
		RequestDispatcher rd = req.getRequestDispatcher("/hserror.jsp");

		rd.forward(req, res);
	}

	protected void checkRequestParams(HttpServletRequest req) throws InvalidClientDataException {

		if (req.getParameter("target") == null || req.getParameter("target").equals("")) {
			throw new InvalidClientDataException("Invalid data from SHIRE: no target URL received.");
		}
		if ((req.getParameter("shire") == null) || (req.getParameter("shire").equals(""))) {
			throw new InvalidClientDataException("Invalid data from SHIRE: No acceptance URL received.");
		}
		if ((req.getRemoteUser() == null) || (req.getRemoteUser().equals(""))) {
			throw new InvalidClientDataException("Unable to authenticate remote user");
		}
		if ((req.getRemoteAddr() == null) || (req.getRemoteAddr().equals(""))) {
			throw new InvalidClientDataException("Unable to obtain client address.");
		}
	}

	class InvalidClientDataException extends Exception {
		public InvalidClientDataException(String message) {
			super(message);
		}
	}

	private class Semaphore {
		private int value;

		public Semaphore(int value) {
			this.value = value;
		}

		public synchronized void enter() throws InterruptedException {
			--value;
			if (value < 0) {
				wait();
			}
		}

		public synchronized void exit() {
			++value;
			notify();
		}
	}

}
