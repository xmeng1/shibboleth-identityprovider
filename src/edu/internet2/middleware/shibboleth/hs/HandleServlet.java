/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation
 * for Advanced Internet Development, Inc. All rights reserved
 * 
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution, if any, must include
 * the following acknowledgment: "This product includes software developed by
 * the University Corporation for Advanced Internet Development
 * <http://www.ucaid.edu> Internet2 Project. Alternately, this acknowledegement
 * may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear.
 * 
 * Neither the name of Shibboleth nor the names of its contributors, nor
 * Internet2, nor the University Corporation for Advanced Internet Development,
 * Inc., nor UCAID may be used to endorse or promote products derived from this
 * software without specific prior written permission. For written permission,
 * please contact shibboleth@shibboleth.org
 * 
 * Products derived from this software may not be called Shibboleth, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor
 * may Shibboleth appear in their name, without prior written permission of the
 * University Corporation for Advanced Internet Development.
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.apache.xerces.parsers.DOMParser;
import org.doomdark.uuid.UUIDGenerator;
import org.opensaml.QName;
import org.opensaml.SAMLAuthorityBinding;
import org.opensaml.SAMLBinding;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
import org.opensaml.SAMLResponse;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import sun.misc.BASE64Decoder;
import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;
import edu.internet2.middleware.shibboleth.common.Credentials;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMapping;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMappingException;
import edu.internet2.middleware.shibboleth.common.RelyingParty;
import edu.internet2.middleware.shibboleth.common.ShibPOSTProfile;
import edu.internet2.middleware.shibboleth.common.ShibResource;
import edu.internet2.middleware.shibboleth.common.ShibbolethOriginConfig;
import edu.internet2.middleware.shibboleth.common.ShibResource.ResourceNotAvailableException;

public class HandleServlet extends HttpServlet {

	private static Logger log = Logger.getLogger(HandleServlet.class.getName());
	private Semaphore throttle;
	private ShibbolethOriginConfig configuration;
	private Credentials credentials;
	private HSNameMapper nameMapper = new HSNameMapper();
	private ShibPOSTProfile postProfile = new ShibPOSTProfile();

	//TODO this is temporary, until we have the mapper
	private RelyingParty relyingParty;

	protected void loadConfiguration() throws HSConfigurationException {

		//TODO This should be setup to do schema checking
		DOMParser parser = new DOMParser();
		String originConfigFile = getInitParameter("OriginConfigFile");
		log.debug("Loading Configuration from (" + originConfigFile + ").");
		try {
			parser.parse(new InputSource(new ShibResource(originConfigFile, this.getClass()).getInputStream()));

		} catch (ResourceNotAvailableException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SAXException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		//Load global configuration properties
		configuration = new ShibbolethOriginConfig(parser.getDocument().getDocumentElement());

		//Load signing credentials
		NodeList itemElements =
			parser.getDocument().getDocumentElement().getElementsByTagNameNS(
				Credentials.credentialsNamespace,
				"Credentials");
		if (itemElements.getLength() < 1) {
			log.error("Credentials not specified.");
			throw new HSConfigurationException("The Handle Service requires that signing credentials be supplied in the <Credentials> configuration element.");
		}

		if (itemElements.getLength() > 1) {
			log.error("Multiple Credentials specifications, using first.");
		}

		credentials = new Credentials((Element) itemElements.item(0));

		//Load name mappings
		itemElements =
			parser.getDocument().getDocumentElement().getElementsByTagNameNS(
				NameIdentifierMapping.mappingNamespace,
				"NameMapping");

		for (int i = 0; i < itemElements.getLength(); i++) {
			try {
				nameMapper.addNameMapping((Element) itemElements.item(i));
			} catch (NameIdentifierMappingException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}

		//TODO this is temporary, until we have the mapper
		relyingParty = new RelyingParty(null, configuration);

	}

	public void init() throws ServletException {
		super.init();
		MDC.put("serviceId", "[HS] Core");
		try {
			log.info("Initializing Handle Service.");

			loadConfiguration();

			throttle =
				new Semaphore(
					Integer.parseInt(
						configuration.getConfigProperty(
							"edu.internet2.middleware.shibboleth.hs.HandleServlet.maxThreads")));

			log.info("Handle Service initialization complete.");

		} catch (HSConfigurationException ex) {
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

			//TODO this is temporary, the first thing to do here is to lookup
			// the relyingParty

			String header =
				relyingParty.getConfigProperty("edu.internet2.middleware.shibboleth.hs.HandleServlet.username");
			String username = header.equalsIgnoreCase("REMOTE_USER") ? req.getRemoteUser() : req.getHeader(header);

			//TODO get right data in here
			SAMLNameIdentifier nameId =
				nameMapper.getNameIdentifierName(null, new AuthNPrincipal(username), relyingParty, null);

			//Print out something better here
			//log.info("Issued Handle (" + handle + ") to (" + username +
			// ")");

			byte[] buf =
				generateAssertion(
					nameId,
					req.getParameter("shire"),
					req.getRemoteAddr(),
					relyingParty.getConfigProperty("edu.internet2.middleware.shibboleth.hs.HandleServlet.authMethod"));

			createForm(req, res, buf);

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

	protected byte[] generateAssertion(
		SAMLNameIdentifier nameId,
		String shireURL,
		String clientAddress,
		String authType)
		throws SAMLException, IOException {

		SAMLAuthorityBinding binding =
			new SAMLAuthorityBinding(
				SAMLBinding.SAML_SOAP_HTTPS,
				relyingParty.getConfigProperty("edu.internet2.middleware.shibboleth.hs.HandleServlet.AAUrl"),
				new QName(org.opensaml.XML.SAMLP_NS, "AttributeQuery"));

		//TODO Scott mentioned the clientAddress should be optional at some
		// point
		SAMLResponse r =
			postProfile.prepare(
				shireURL,
				relyingParty,
				nameId,
				clientAddress,
				authType,
				new Date(System.currentTimeMillis()),
				Collections.singleton(binding),
				credentials.getCredential(
					relyingParty.getConfigProperty(
						"edu.internet2.middleware.shibboleth.hs.HandleServlet.responseCredential")),
				null);

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
