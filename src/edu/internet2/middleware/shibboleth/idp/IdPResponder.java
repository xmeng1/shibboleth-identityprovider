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
import java.util.HashMap;
import java.util.Iterator;
import java.util.Random;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

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
import edu.internet2.middleware.shibboleth.common.ServiceProviderMapper;
import edu.internet2.middleware.shibboleth.common.ServiceProviderMapperException;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.log.LoggingInitializer;
import edu.internet2.middleware.shibboleth.metadata.Metadata;
import edu.internet2.middleware.shibboleth.metadata.MetadataException;

/**
 * Primary entry point for requests to the SAML IdP. Listens on multiple endpoints, routes requests to the appropriate
 * IdP processing components, and delivers proper protocol responses.
 * 
 * @author Walter Hoehn
 */

public class IdPResponder extends HttpServlet {

	private static Logger transactionLog;
	private static Logger log;
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

		try {
			binding = SAMLBindingFactory.getInstance(SAMLBinding.SOAP);

			Document idPConfig = IdPConfigLoader.getIdPConfig(this.getServletContext());

			// Initialize logging
			NodeList itemElements = idPConfig.getDocumentElement().getElementsByTagNameNS(IdPConfig.configNameSpace,
					"Logging");
			if (itemElements.getLength() > 0) {
				if (itemElements.getLength() > 1) {
					System.err
							.println("WARNING: More than one Logging element in IdP configuration, using the first one.");
				} else {
					Element loggingConfig = (Element) itemElements.item(0);
					LoggingInitializer.initializeLogging(loggingConfig);
				}
			} else {
				LoggingInitializer.initializeLogging();
			}

			transactionLog = Logger.getLogger("Shibboleth-TRANSACTION");
			log = Logger.getLogger(IdPResponder.class);
			MDC.put("serviceId", "[IdP] Core");
			log.info("Initializing Identity Provider.");

			// Load global configuration properties
			configuration = new IdPConfig(idPConfig.getDocumentElement());

			// Load name mappings
			NameMapper nameMapper = new NameMapper();
			itemElements = idPConfig.getDocumentElement().getElementsByTagNameNS(
					NameIdentifierMapping.mappingNamespace, "NameMapping");

			for (int i = 0; i < itemElements.getLength(); i++) {
				try {
					nameMapper.addNameMapping((Element) itemElements.item(i));
				} catch (NameIdentifierMappingException e) {
					log.error("Name Identifier mapping could not be loaded: " + e);
				}
			}

			// Load signing credentials
			itemElements = idPConfig.getDocumentElement().getElementsByTagNameNS(Credentials.credentialsNamespace,
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
				spMapper = new ServiceProviderMapper(idPConfig.getDocumentElement(), configuration, credentials,
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

				itemElements = idPConfig.getDocumentElement().getElementsByTagNameNS(IdPConfig.configNameSpace,
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
			itemElements = idPConfig.getDocumentElement().getElementsByTagNameNS(IdPConfig.configNameSpace,
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
			itemElements = idPConfig.getDocumentElement().getElementsByTagNameNS(IdPConfig.configNameSpace,
					"ProtocolHandler");

			// Default if no handlers are specified
			if (itemElements.getLength() < 1) {
				itemElements = getDefaultHandlers();

				// If handlers were specified, load them and register them against their locations
			}
			EACHHANDLER : for (int i = 0; i < itemElements.getLength(); i++) {
				IdPProtocolHandler handler = ProtocolHandlerFactory.getInstance((Element) itemElements.item(i));
				String[] locations = handler.getLocations();
				EACHLOCATION : for (int j = 0; j < locations.length; j++) {
					if (protocolHandlers.containsKey(locations[j])) {
						log.error("Multiple protocol handlers are registered to listen at (" + locations[j]
								+ ").  Ignoring all except ("
								+ ((IdPProtocolHandler) protocolHandlers.get(locations[j])).getHandlerName() + ").");
						continue EACHLOCATION;
					}
					log.info("Registering handler (" + handler.getHandlerName() + ") to listen at (" + locations[j]
							+ ").");
					protocolHandlers.put(locations[j].toString(), handler);
				}
			}

			// Load metadata
			itemElements = idPConfig.getDocumentElement().getElementsByTagNameNS(IdPConfig.configNameSpace,
					"MetadataProvider");
			for (int i = 0; i < itemElements.getLength(); i++) {
				protocolSupport.addMetadataProvider((Element) itemElements.item(i));
			}
			if (protocolSupport.providerCount() < 1) {
				log.error("No Metadata Provider metadata loaded.");
				throw new ShibbolethConfigurationException("Could not load SAML metadata.");
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
			IdPProtocolHandler activeHandler = lookupProtocolHandler(request);
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
				samlRequest = binding.receive(request, 1);
			} catch (SAMLException e) {
				log.fatal("Unable to parse request: " + e);
				throw new SAMLException("Invalid request data.");
			}

			// If we have DEBUG logging turned on, dump out the request to the log
			// This takes some processing, so only do it if we need to
			if (log.isDebugEnabled()) {
				log.debug("Dumping generated SAML Request:" + System.getProperty("line.separator")
						+ samlRequest.toString());
			}

			IdPProtocolHandler activeHandler = lookupProtocolHandler(request);
			// Pass request to the appropriate handler and respond
			log.info("Processing " + activeHandler.getHandlerName() + " request.");

			SAMLResponse samlResponse = activeHandler.processRequest(request, response, samlRequest, protocolSupport);
			binding.respond(response, samlResponse, null);

		} catch (SAMLException e) {
			sendFailureToSAMLBinding(response, samlRequest, e);
		}
	}

	private IdPProtocolHandler lookupProtocolHandler(HttpServletRequest request) throws SAMLException {

		// Determine which protocol handler is active for this endpoint
		String requestURL = request.getRequestURL().toString();
		IdPProtocolHandler activeHandler = null;

		Iterator registeredLocations = protocolHandlers.keySet().iterator();
		while (registeredLocations.hasNext()) {
			String handlerLocation = (String) registeredLocations.next();
			if (requestURL.matches(handlerLocation)) {
				log.debug("Matched handler location: (" + handlerLocation + ").");
				activeHandler = (IdPProtocolHandler) protocolHandlers.get(handlerLocation);
				break;
			}
		}

		if (activeHandler == null) {
			log.error("No protocol handler registered for location (" + request.getRequestURL() + ").");
			throw new SAMLException("Request submitted to an invalid location.");
		}
		return activeHandler;
	}

	private NodeList getDefaultHandlers() throws ShibbolethConfigurationException {

		log.debug("Loading default protocol handler configuration.");
		try {
			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			docFactory.setNamespaceAware(true);
			Document placeHolder = docFactory.newDocumentBuilder().newDocument();
			Element baseNode = placeHolder.createElementNS(IdPConfig.configNameSpace, "IdPConfig");

			Element ssoHandler = placeHolder.createElementNS(IdPConfig.configNameSpace, "ProtocolHandler");
			ssoHandler.setAttribute("implementation",
					"edu.internet2.middleware.shibboleth.idp.provider.ShibbolethV1SSOHandler");
			Element ssoLocation = placeHolder.createElementNS(IdPConfig.configNameSpace, "Location");
			ssoLocation.appendChild(placeHolder.createTextNode("https?://[^/]+(:443)?/shibboleth/SSO"));
			ssoHandler.appendChild(ssoLocation);
			baseNode.appendChild(ssoHandler);

			Element attributeHandler = placeHolder.createElementNS(IdPConfig.configNameSpace, "ProtocolHandler");
			attributeHandler.setAttribute("implementation",
					"edu.internet2.middleware.shibboleth.idp.provider.SAMLv1_AttributeQueryHandler");
			Element attributeLocation = placeHolder.createElementNS(IdPConfig.configNameSpace, "Location");
			attributeLocation.appendChild(placeHolder.createTextNode("https?://[^/]+:8443/shibboleth/AA"));
			attributeHandler.appendChild(attributeLocation);
			baseNode.appendChild(attributeHandler);

			Element artifactHandler = placeHolder.createElementNS(IdPConfig.configNameSpace, "ProtocolHandler");
			artifactHandler.setAttribute("implementation",
					"edu.internet2.middleware.shibboleth.idp.provider.SAMLv1_1ArtifactQueryHandler");
			Element artifactLocation = placeHolder.createElementNS(IdPConfig.configNameSpace, "Location");
			artifactLocation.appendChild(placeHolder.createTextNode("https?://[^/]+:8443/shibboleth/Artifact"));
			artifactHandler.appendChild(artifactLocation);
			baseNode.appendChild(artifactHandler);

			return baseNode.getElementsByTagNameNS(IdPConfig.configNameSpace, "ProtocolHandler");

		} catch (ParserConfigurationException e) {
			log.fatal("Encoutered an error while loading default protocol handlers: " + e);
			throw new ShibbolethConfigurationException("Could not load protocol handlers.");
		}
	}

	private void sendFailureToSAMLBinding(HttpServletResponse httpResponse, SAMLRequest samlRequest,
			SAMLException exception) throws ServletException {

		log.error("Error while processing request: " + exception);
		try {
			SAMLResponse samlResponse = new SAMLResponse((samlRequest != null) ? samlRequest.getId() : null, null,
					null, exception);
			if (log.isDebugEnabled()) {
				log.debug("Dumping generated SAML Error Response:" + System.getProperty("line.separator")
						+ samlResponse.toString());
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

class MetadataProviderFactory {

	private static Logger log = Logger.getLogger(MetadataProviderFactory.class.getName());

	public static Metadata loadProvider(Element e) throws MetadataException {

		String className = e.getAttribute("type");
		if (className == null || className.equals("")) {
			log.error("Metadata Provider requires specification of the attribute \"type\".");
			throw new MetadataException("Failed to initialize Metadata Provider.");
		} else {
			try {
				Class[] params = {Class.forName("org.w3c.dom.Element"),};
				return (Metadata) Class.forName(className).getConstructor(params).newInstance(new Object[]{e});
			} catch (Exception loaderException) {
				log.error("Failed to load Metadata Provider implementation class: " + loaderException);
				Throwable cause = loaderException.getCause();
				while (cause != null) {
					log.error("caused by: " + cause);
					cause = cause.getCause();
				}
				throw new MetadataException("Failed to initialize Metadata Provider.");
			}
		}
	}
}