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

import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.opensaml.Configuration;
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
import edu.internet2.middleware.shibboleth.common.RelyingPartyMapper;
import edu.internet2.middleware.shibboleth.common.RelyingPartyMapperException;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.log.LoggingInitializer;

/**
 * Primary entry point for requests to the Shibboleth IdP. Listens on multiple endpoints, routes requests to the
 * appropriate IdP processing components, and delivers proper protocol responses.
 * 
 * @author Walter Hoehn
 */

public class IdPResponder extends HttpServlet {

	private static Logger transactionLog;
	private static Logger log;
	private static Random idgen = new Random();

	private IdPConfig configuration;
	private Map<String, IdPProtocolHandler> protocolHandlers = new HashMap<String, IdPProtocolHandler>();
	private IdPProtocolSupport protocolSupport;

	/*
	 * @see javax.servlet.GenericServlet#init()
	 */
	@SuppressWarnings("unused")
	public void init(ServletConfig servletConfig) throws ServletException {

		super.init(servletConfig);

		// Load OpenSAML2
		Configuration.init();

		try {
			Document idPConfig = IdPConfigLoader.getIdPConfig(this.getServletContext());

			// Initialize logging
			NodeList itemElements = idPConfig.getDocumentElement().getElementsByTagNameNS(IdPConfig.configNameSpace,
					"Logging");
			if (itemElements.getLength() > 0) {
				if (itemElements.getLength() > 1) {
					System.err.println("WARNING: More than one Logging element in IdP configuration, "
							+ "using the first one.");
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
			RelyingPartyMapper spMapper;
			try {
				spMapper = new RelyingPartyMapper(idPConfig.getDocumentElement(), credentials);
			} catch (RelyingPartyMapperException e) {
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
			protocolSupport = new IdPProtocolSupport(configuration, transactionLog, spMapper, arpEngine, resolver,
					artifactMapper);
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
			servletConfig.getServletContext().log("The Identity Provider could not be initialized: " + ae);
			if (log != null) {
				log.fatal("The Identity Provider could not be initialized: " + ae);
			}
			throw new UnavailableException("Identity Provider failed to initialize.");
		}
	}

	/*
	 * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

		log.debug("Received a request via GET for location (" + request.getRequestURL() + ").");

		try {
			processRequest(request, response);

		} catch (RequestHandlingException e) {
			log.error("Error while processing GET request: " + e);
			sendGenericGetError(request, response, e);
		} finally {
			MDC.remove("serviceId");
			MDC.remove("remoteAddr");
		}
	}

	/*
	 * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

		log.debug("Received a request via POST for location (" + request.getRequestURL() + ").");

		try {
			processRequest(request, response);

		} catch (RequestHandlingException e) {
			log.error("Error while processing POST request: " + e);
			sendGenericPostError(response, e);
		} finally {
			MDC.remove("serviceId");
			MDC.remove("remoteAddr");
		}
	}

	/**
	 * Refers the request to the appropriate protocol handler
	 */
	private void processRequest(HttpServletRequest request, HttpServletResponse response)
			throws RequestHandlingException, ServletException {

		MDC.put("serviceId", "[IdP] " + idgen.nextInt());
		MDC.put("remoteAddr", request.getRemoteAddr());

		IdPProtocolHandler activeHandler = lookupProtocolHandler(request);
		// Pass request to the appropriate handler and respond
		log.info("Processing " + activeHandler.getHandlerName() + " request.");
		activeHandler.processRequest(request, response, protocolSupport);
	}

	/** Determine which protocol handler is active for this endpoint */
	private IdPProtocolHandler lookupProtocolHandler(HttpServletRequest request) throws RequestHandlingException {

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
			throw new RequestHandlingException("Request submitted to an invalid location.");
		}
		return activeHandler;
	}

	/**
	 * Specifies a default set of IDPProtocolHandler configurations that should be used if none are specified in the IdP
	 * configuration.
	 */
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

	/**
	 * Generic error response for GET requests.
	 */
	private void sendGenericPostError(HttpServletResponse httpResponse, RequestHandlingException exception)
			throws ServletException {

		try {
			httpResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error while responding.");
		} catch (IOException ee) {
			log.fatal("Could not construct a SAML error response: " + ee);
			throw new ServletException("Identity Provider response failure.");
		}
	}

	/**
	 * Generic error response for GET requests.
	 */
	private void sendGenericGetError(HttpServletRequest req, HttpServletResponse res, RequestHandlingException e)
			throws ServletException, IOException {

		req.setAttribute("errorText", e.toString());
		req.setAttribute("requestURL", req.getRequestURI().toString());
		RequestDispatcher rd = req.getRequestDispatcher("/IdPError.jsp");
		rd.forward(req, res);
	}

}
