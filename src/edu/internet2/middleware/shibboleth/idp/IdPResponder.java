/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
 * provided with the distribution, if any, must include the following acknowledgment: "This product includes software
 * developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu> Internet2 Project.
 * Alternately, this acknowledegement may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear. Neither the name of Shibboleth nor the names of its contributors, nor Internet2, nor
 * the University Corporation for Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote
 * products derived from this software without specific prior written permission. For written permission, please contact
 * shibboleth@shibboleth.org Products derived from this software may not be called Shibboleth, Internet2, UCAID, or the
 * University Corporation for Advanced Internet Development, nor may Shibboleth appear in their name, without prior
 * written permission of the University Corporation for Advanced Internet Development. THIS SOFTWARE IS PROVIDED BY THE
 * COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE
 * DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. IN NO
 * EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC.
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.idp;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.Random;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.opensaml.SAMLBinding;
import org.opensaml.SAMLBindingFactory;
import org.opensaml.SAMLException;
import org.opensaml.SAMLRequest;
import org.opensaml.SAMLResponse;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import sun.misc.BASE64Decoder;
import edu.internet2.middleware.shibboleth.aa.arp.ArpEngine;
import edu.internet2.middleware.shibboleth.aa.arp.ArpException;
import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver;
import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolverException;
import edu.internet2.middleware.shibboleth.artifact.ArtifactMapper;
import edu.internet2.middleware.shibboleth.artifact.ArtifactMapperFactory;
import edu.internet2.middleware.shibboleth.artifact.provider.MemoryArtifactMapper;
import edu.internet2.middleware.shibboleth.common.Credentials;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMapping;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMappingException;
import edu.internet2.middleware.shibboleth.common.NameMapper;
import edu.internet2.middleware.shibboleth.common.OriginConfig;
import edu.internet2.middleware.shibboleth.common.ServiceProviderMapper;
import edu.internet2.middleware.shibboleth.common.ServiceProviderMapperException;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.metadata.Metadata;
import edu.internet2.middleware.shibboleth.metadata.MetadataException;

/**
 * Primary entry point for requests to the SAML IdP. Listens on multiple endpoints, routes requests to the appropriate
 * IdP processing components, and delivers proper protocol responses.
 * 
 * @author Walter Hoehn
 */

public class IdPResponder extends HttpServlet {

	private static Logger transactionLog = Logger.getLogger("Shibboleth-TRANSACTION");
	private static Logger log = Logger.getLogger(IdPResponder.class.getName());
	private static Random idgen = new Random();
	private SAMLBinding binding;

	private IdPConfig configuration;
	private HashMap protocolHandlers = new HashMap();
	private IdPProtocolSupport protocolSupport;

	/*
	 * @see javax.servlet.GenericServlet#init()
	 */
	public void init() throws ServletException {

		super.init();
		MDC.put("serviceId", "[IdP] Core");
		log.info("Initializing Identity Provider.");

		try {
			binding = SAMLBindingFactory.getInstance(SAMLBinding.SOAP);

			Document originConfig = OriginConfig.getOriginConfig(this.getServletContext());

			// Load global configuration properties
			configuration = new IdPConfig(originConfig.getDocumentElement());

			// Load name mappings
			NameMapper nameMapper = new NameMapper();
			NodeList itemElements = originConfig.getDocumentElement().getElementsByTagNameNS(
					NameIdentifierMapping.mappingNamespace, "NameMapping");

			for (int i = 0; i < itemElements.getLength(); i++) {
				try {
					nameMapper.addNameMapping((Element) itemElements.item(i));
				} catch (NameIdentifierMappingException e) {
					log.error("Name Identifier mapping could not be loaded: " + e);
				}
			}

			// Load signing credentials
			itemElements = originConfig.getDocumentElement().getElementsByTagNameNS(Credentials.credentialsNamespace,
					"Credentials");
			if (itemElements.getLength() < 1) {
				log.error("No credentials specified.");
			}
			if (itemElements.getLength() > 1) {
				log.error("Multiple Credentials specifications found, using first.");
			}
			Credentials credentials = new Credentials((Element) itemElements.item(0));

			// Load relying party config
			ServiceProviderMapper spMapper;
			try {
				spMapper = new ServiceProviderMapper(originConfig.getDocumentElement(), configuration, credentials,
						nameMapper);
			} catch (ServiceProviderMapperException e) {
				log.error("Could not load Identity Provider configuration: " + e);
				throw new ShibbolethConfigurationException("Could not load Identity Provider configuration.");
			}

			// Startup Attribute Resolver & ARP engine
			AttributeResolver resolver = null;
			ArpEngine arpEngine = null;
			try {
				resolver = new AttributeResolver(configuration);

				itemElements = originConfig.getDocumentElement().getElementsByTagNameNS(IdPConfig.configNameSpace,
						"ReleasePolicyEngine");

				if (itemElements.getLength() > 1) {
					log.warn("Encountered multiple <ReleasePolicyEngine/> configuration elements.  Using first...");
				}
				if (itemElements.getLength() < 1) {
					arpEngine = new ArpEngine();
				} else {
					arpEngine = new ArpEngine((Element) itemElements.item(0));
				}

			} catch (ArpException ae) {
				log.fatal("The Identity Provider could not be initialized "
						+ "due to a problem with the ARP Engine configuration: " + ae);
				throw new ShibbolethConfigurationException("Could not load ARP Engine.");
			} catch (AttributeResolverException ne) {
				log.fatal("The Identity Provider could not be initialized due "
						+ "to a problem with the Attribute Resolver configuration: " + ne);
				throw new ShibbolethConfigurationException("Could not load Attribute Resolver.");
			}

			// Load artifact mapping implementation
			ArtifactMapper artifactMapper = null;
			itemElements = originConfig.getDocumentElement().getElementsByTagNameNS(IdPConfig.configNameSpace,
					"ArtifactMapper");
			if (itemElements.getLength() > 1) {
				log.warn("Encountered multiple <ArtifactMapper/> configuration elements.  Using first...");
			}
			if (itemElements.getLength() > 0) {
				artifactMapper = ArtifactMapperFactory.getInstance((Element) itemElements.item(0));
			} else {
				log.debug("No Artifact Mapper configuration found.  Defaulting to Memory-based implementation.");
				artifactMapper = new MemoryArtifactMapper();
			}

			// Load protocol handlers and support library
			protocolSupport = new IdPProtocolSupport(configuration, transactionLog, nameMapper, spMapper, arpEngine,
					resolver, artifactMapper);
			itemElements = originConfig.getDocumentElement().getElementsByTagNameNS(IdPConfig.configNameSpace,
					"ProtocolHandler");

			// Default if no handlers are specified
			if (itemElements.getLength() < 1) {
				// TODO work out defaulting

				// If handlers were specified, load them and register them against their locations
			} else {
				EACHHANDLER : for (int i = 0; i < itemElements.getLength(); i++) {
					IdPProtocolHandler handler = ProtocolHandlerFactory.getInstance((Element) itemElements.item(i));
					URI[] locations = handler.getLocations();
					EACHLOCATION : for (int j = 0; j < locations.length; j++) {
						if (protocolHandlers.containsKey(locations[j].toString())) {
							log.error("Multiple protocol handlers are registered to listen at ("
									+ locations[j]
									+ ").  Ignoring all except ("
									+ ((IdPProtocolHandler) protocolHandlers.get(locations[j].toString()))
											.getHandlerName() + ").");
							continue EACHLOCATION;
						}
						log.info("Registering handler (" + handler.getHandlerName() + ") to listen at (" + locations[j]
								+ ").");
						protocolHandlers.put(locations[j].toString(), handler);
					}
				}
			}

			// Load metadata
			itemElements = originConfig.getDocumentElement().getElementsByTagNameNS(IdPConfig.configNameSpace,
					"FederationProvider");
			for (int i = 0; i < itemElements.getLength(); i++) {
				protocolSupport.addFederationProvider((Element) itemElements.item(i));
			}
			if (protocolSupport.providerCount() < 1) {
				log.error("No Federation Provider metadata loaded.");
				throw new ShibbolethConfigurationException("Could not load federation metadata.");
			}

			log.info("Identity Provider initialization complete.");

		} catch (ShibbolethConfigurationException ae) {
			log.fatal("The Identity Provider could not be initialized: " + ae);
			throw new UnavailableException("Identity Provider failed to initialize.");
		} catch (SAMLException se) {
			log.fatal("SAML SOAP binding could not be loaded: " + se);
			throw new UnavailableException("Identity Provider failed to initialize.");
		}
	}

	/*
	 * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

		MDC.put("serviceId", "[IdP] " + idgen.nextInt());
		MDC.put("remoteAddr", request.getRemoteAddr());
		log.debug("Recieved a request via GET for location (" + request.getRequestURL() + ").");

		try {
			// Determine which protocol we are responding to (at this point normally Shibv1 vs. EAuth)
			String requestURL = request.getRequestURL().toString();
			IdPProtocolHandler activeHandler = (IdPProtocolHandler) protocolHandlers.get(requestURL);
			if (activeHandler == null) {
				log.debug("No protocol handler registered for location (" + request.getRequestURL()
						+ ").  Attempting to match against relative path.");
				try {
					activeHandler = (IdPProtocolHandler) protocolHandlers.get(new URL(requestURL).getPath());
				} catch (MalformedURLException e) {
					// squelch, we will just fail to find a handler
				}
			}

			if (activeHandler == null) {
				log.error("No protocol handler registered for location (" + request.getRequestURL() + ").");
				throw new SAMLException("Request submitted to an invalid location.");
			}

			// Pass request to the appropriate handler
			log.info("Processing " + activeHandler.getHandlerName() + " request.");
			if (activeHandler.processRequest(request, response, null, protocolSupport) != null) {
				// This shouldn't happen unless somebody configures a protocol handler incorrectly
				log.error("Protocol Handler returned a SAML Response, but there is no binding to handle it.");
				throw new SAMLException(SAMLException.RESPONDER, "General error processing request.");
			}

		} catch (SAMLException ex) {
			log.error(ex);
			displayBrowserError(request, response, ex);
			return;
		}
	}

	/*
	 * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

		MDC.put("serviceId", "[IdP] " + idgen.nextInt());
		MDC.put("remoteAddr", request.getRemoteAddr());
		log.debug("Recieved a request via POST for location (" + request.getRequestURL() + ").");

		// Parse SOAP request and marshall SAML request object
		SAMLRequest samlRequest = null;
		try {
			try {
				samlRequest = binding.receive(request);
			} catch (SAMLException e) {
				log.fatal("Unable to parse request: " + e);
				throw new SAMLException("Invalid request data.");
			}

			// If we have DEBUG logging turned on, dump out the request to the log
			// This takes some processing, so only do it if we need to
			if (log.isDebugEnabled()) {
				try {
					log.debug("Dumping generated SAML Request:"
							+ System.getProperty("line.separator")
							+ new String(new BASE64Decoder().decodeBuffer(new String(samlRequest.toBase64(), "ASCII")),
									"UTF8"));
				} catch (SAMLException e) {
					log.error("Encountered an error while decoding SAMLRequest for logging purposes.");
				} catch (IOException e) {
					log.error("Encountered an error while decoding SAMLRequest for logging purposes.");
				}
			}

			// Determine which protocol handler is active for this endpoint
			String requestURL = request.getRequestURL().toString();
			IdPProtocolHandler activeHandler = (IdPProtocolHandler) protocolHandlers.get(requestURL);
			if (activeHandler == null) {
				log.debug("No protocol handler registered for location (" + request.getRequestURL()
						+ ").  Attempting to match against relative path.");
				try {
					activeHandler = (IdPProtocolHandler) protocolHandlers.get(new URL(requestURL).getPath());
				} catch (MalformedURLException e) {
					// squelch, we will just fail to find a handler
				}
			}

			// Pass request to the appropriate handler and respond
			log.info("Processing " + activeHandler.getHandlerName() + " request.");

			SAMLResponse samlResponse = activeHandler.processRequest(request, response, samlRequest, protocolSupport);
			binding.respond(response, samlResponse, null);

		} catch (SAMLException e) {
			sendFailureToSAMLBinding(response, samlRequest, e);
		}
	}

	private void sendFailureToSAMLBinding(HttpServletResponse httpResponse, SAMLRequest samlRequest,
			SAMLException exception) throws ServletException {

		log.error("Error while processing request: " + exception);
		try {
			SAMLResponse samlResponse = new SAMLResponse((samlRequest != null) ? samlRequest.getId() : null, null,
					null, exception);
			if (log.isDebugEnabled()) {
				try {
					log.debug("Dumping generated SAML Error Response:"
							+ System.getProperty("line.separator")
							+ new String(
									new BASE64Decoder().decodeBuffer(new String(samlResponse.toBase64(), "ASCII")),
									"UTF8"));
				} catch (IOException e) {
					log.error("Encountered an error while decoding SAMLReponse for logging purposes.");
				}
			}
			binding.respond(httpResponse, samlResponse, null);
			log.debug("Returning SAML Error Response.");
		} catch (SAMLException se) {
			try {
				binding.respond(httpResponse, null, exception);
			} catch (SAMLException e) {
				log.error("Caught exception while responding to requester: " + e.getMessage());
				try {
					httpResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error while responding.");
				} catch (IOException ee) {
					log.fatal("Could not construct a SAML error response: " + ee);
					throw new ServletException("Identity Provider response failure.");
				}
			}
			log.error("Identity Provider failed to make an error message: " + se);
		}
	}

	private static void displayBrowserError(HttpServletRequest req, HttpServletResponse res, Exception e)
			throws ServletException, IOException {

		req.setAttribute("errorText", e.toString());
		req.setAttribute("requestURL", req.getRequestURI().toString());
		RequestDispatcher rd = req.getRequestDispatcher("/IdPError.jsp");
		rd.forward(req, res);
	}

}

class FederationProviderFactory {

	private static Logger log = Logger.getLogger(FederationProviderFactory.class.getName());

	public static Metadata loadProvider(Element e) throws MetadataException {

		String className = e.getAttribute("type");
		if (className == null || className.equals("")) {
			log.error("Federation Provider requires specification of the attribute \"type\".");
			throw new MetadataException("Failed to initialize Federation Provider.");
		} else {
			try {
				Class[] params = {Class.forName("org.w3c.dom.Element"),};
				return (Metadata) Class.forName(className).getConstructor(params).newInstance(new Object[]{e});
			} catch (Exception loaderException) {
				log.error("Failed to load Federation Provider implementation class: " + loaderException);
				Throwable cause = loaderException.getCause();
				while (cause != null) {
					log.error("caused by: " + cause);
					cause = cause.getCause();
				}
				throw new MetadataException("Failed to initialize Federation Provider.");
			}
		}
	}
}