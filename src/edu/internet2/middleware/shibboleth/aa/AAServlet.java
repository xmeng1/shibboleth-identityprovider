/* 
 * The Shibboleth License, Version 1. 
 * Copyright (c) 2002 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
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
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement 
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
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.aa;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Principal;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.servlet.ServletException;
import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.opensaml.QName;
import org.opensaml.SAMLException;
import org.opensaml.SAMLIdentifier;

import edu.internet2.middleware.eduPerson.Init;
import edu.internet2.middleware.shibboleth.aa.arp.ArpEngine;
import edu.internet2.middleware.shibboleth.aa.arp.ArpException;
import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;
import edu.internet2.middleware.shibboleth.common.ShibResource;
import edu.internet2.middleware.shibboleth.hs.HandleRepository;
import edu.internet2.middleware.shibboleth.hs.HandleRepositoryException;
import edu.internet2.middleware.shibboleth.hs.HandleRepositoryFactory;
import edu.internet2.middleware.shibboleth.hs.InvalidHandleException;

/**
 *  Attribute Authority & Release Policy
 *  Handles Initialization and incoming requests to AA
 *
 * @author Parviz Dousti (dousti@cmu.edu)
 * @author	Walter Hoehn (wassa@columbia.edu)
 */

public class AAServlet extends HttpServlet {

    protected AAResponder responder;
    protected HandleRepository handleRepository;
    protected Properties configuration;
    private static Logger log = Logger.getLogger(AAServlet.class.getName());    
    
	public void init() throws ServletException {
		super.init();

		MDC.put("serviceId", "[AA] Core");
		log.info("Initializing Attribute Authority.");

		try {

			configuration = loadConfiguration();

			ArpEngine arpEngine = new ArpEngine(configuration);
			
			handleRepository = HandleRepositoryFactory.getInstance(configuration);

			log.info(
				"Using JNDI context ("
					+ configuration.getProperty("java.naming.factory.initial")
					+ ") for attribute retrieval.");

			DirContext ctx = new InitialDirContext(configuration);
			Init.init();
			responder =
				new AAResponder(
					arpEngine,
					ctx,
					configuration.getProperty(
						"edu.internet2.middleware.shibboleth.aa.AAServlet.authorityName"));

			log.info("Attribute Authority initialization complete.");

		} catch (NamingException ne) {
			log.fatal(
				"The AA could not be initialized due to a problem with the JNDI context configuration: "
					+ ne);
			throw new UnavailableException("Attribute Authority failed to initialize.");
		} catch (ArpException ae) {
			log.fatal(
				"The AA could not be initialized due to a problem with the ARP Engine configuration: " + ae);
			throw new UnavailableException("Attribute Authority failed to initialize.");
		} catch (AAException ae) {
			log.fatal("The AA could not be initialized: " + ae);
			throw new UnavailableException("Attribute Authority failed to initialize.");
		} catch (HandleRepositoryException he) {
			log.fatal(
				"The AA could not be initialized due to a problem with the Handle Repository configuration: "
					+ he);
			throw new UnavailableException("Attribute Authority failed to initialize.");
		}
	}
	protected Properties loadConfiguration() throws AAException {

		//Set defaults
		Properties defaultProps = new Properties();
		defaultProps.setProperty(
			"edu.internet2.middleware.shibboleth.aa.arp.provider.FileSystemArpRepository.Path",
			"/conf/arps/");
		defaultProps.setProperty(
			"edu.internet2.middleware.shibboleth.aa.arp.ArpRepository.implementation",
			"edu.internet2.middleware.shibboleth.aa.arp.provider.FileSystemArpRepository");
		defaultProps.setProperty("edu.internet2.middleware.shibboleth.aa.AAServlet.ldapUserDnPhrase", "uid=");
		defaultProps.setProperty(
			"java.naming.factory.initial",
			"edu.internet2.middleware.shibboleth.aaLocal.EchoCtxFactory");
		defaultProps.setProperty(
			"edu.internet2.middleware.shibboleth.hs.provider.CryptoHandleRepository.keyStorePath",
			"/conf/handle.jks");
		defaultProps.setProperty("edu.internet2.middleware.shibboleth.audiences", "urn:mace:InCommon:pilot:2003");
		defaultProps.setProperty("edu.internet2.middleware.shibboleth.aa.AAServlet.passThruErrors", "false");

		//Load from file
		Properties properties = new Properties(defaultProps);
		String propertiesFileLocation = getInitParameter("OriginPropertiesFile");
		if (propertiesFileLocation == null) {
			propertiesFileLocation = "/conf/origin.properties";
		}
		try {
			log.debug("Loading Configuration from (" + propertiesFileLocation + ").");
			properties.load(new ShibResource(propertiesFileLocation, this.getClass()).getInputStream());

			//Make sure we have all required parameters
			StringBuffer missingProperties = new StringBuffer();
			String[] requiredProperties =
				{
					"edu.internet2.middleware.shibboleth.aa.AAServlet.authorityName",
					"java.naming.factory.initial",
					"edu.internet2.middleware.shibboleth.aa.arp.ArpRepository.implementation",
					"edu.internet2.middleware.shibboleth.audiences" };

			for (int i = 0; i < requiredProperties.length; i++) {
				if (properties.getProperty(requiredProperties[i]) == null) {
					missingProperties.append("\"");
					missingProperties.append(requiredProperties[i]);
					missingProperties.append("\" ");
				}
			}
			if (missingProperties.length() > 0) {
				log.error(
					"Missing configuration data.  The following configuration properites have not been set: "
						+ missingProperties.toString());
				throw new AAException("Missing configuration data.");
			}

		} catch (IOException e) {
			log.error("Could not load AA servlet configuration: " + e);
			throw new AAException("Could not load AA servlet configuration.");
		}

		if (log.isDebugEnabled()) {
			ByteArrayOutputStream debugStream = new ByteArrayOutputStream();
			PrintStream debugPrinter = new PrintStream(debugStream);
			properties.list(debugPrinter);
			log.debug(
				"Runtime configuration parameters: " + System.getProperty("line.separator") + debugStream.toString());
			try {
				debugStream.close();
			} catch (IOException e) {
				log.error("Encountered a problem cleaning up resources: could not close debug stream.");
			}
		}

		return properties;
	}

	public void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

		log.debug("Recieved a request.");
		MDC.put("serviceId", "[AA] " + new SAMLIdentifier().toString());
		MDC.put("remoteAddr", req.getRemoteAddr());
		log.info("Handling request.");

		AASaml saml = null;

		try {
			saml =
				new AASaml(
					configuration.getProperty("edu.internet2.middleware.shibboleth.aa.AAServlet.authorityName"),
					configuration.getProperty("edu.internet2.middleware.shibboleth.audiences").replaceAll(
						"\\s",
						"").split(
						","));
			saml.receive(req);

			log.info("Attribute Query Handle for this request: (" + saml.getHandle() + ").");
			Principal principal = null;
			if (saml.getHandle().equalsIgnoreCase("foo")) {
				// for testing
				principal = new AuthNPrincipal("test-handle");
			} else {
				principal = handleRepository.getPrincipal(saml.getHandle());
			}

			URL resource = null;
			try {
				resource = new URL(saml.getResource());
			} catch (MalformedURLException mue) {
				log.error(
					"Request contained an improperly formatted resource identifier.  Attempting to "
						+ "handle request without one.");
			}

			if (saml.getShar() == null) {
				log.info("Request is from an unauthenticated SHAR.");
			} else {
				log.info("Request is from SHAR: (" + saml.getShar() + ").");
			}

			List attrs =
				Arrays.asList(
					responder.getReleaseAttributes(
						principal,
						configuration.getProperty("edu.internet2.middleware.shibboleth.aa.AAServlet.ldapUserDnPhrase"),
						saml.getShar(),
						resource));
			log.info("Got " + attrs.size() + " attributes for " + principal.getName());
			saml.respond(resp, attrs, null);
			log.info("Successfully responded about " + principal.getName());

		} catch (InvalidHandleException e) {
			log.info("Could not associate the Attribute Query Handle with a principal: " + e);
			try {
				QName[] codes =
					{
						SAMLException.REQUESTER,
						new QName(edu.internet2.middleware.shibboleth.common.XML.SHIB_NS, "InvalidHandle")};
				if (configuration
					.getProperty("edu.internet2.middleware.shibboleth.aa.AAServlet.passThruErrors", "false")
					.equals("true")) {
					saml.fail(
						resp,
						new SAMLException(
							Arrays.asList(codes),
							"The supplied Attribute Query Handle was unrecognized or expired."));
				} else {
					saml.fail(resp, new SAMLException(Arrays.asList(codes), e));
				}
				return;
			} catch (Exception ee) {
				log.fatal("Could not construct a SAML error response: " + ee);
				throw new ServletException("Attribute Authority response failure.");
			}

		} catch (Exception e) {
			log.error("Error while processing request: " + e);
			try {
				if (configuration
					.getProperty("edu.internet2.middleware.shibboleth.aa.AAServlet.passThruErrors", "false")
					.equals("true")) {
					saml.fail(resp, new SAMLException(SAMLException.RESPONDER, e));
				} else {
					saml.fail(resp, new SAMLException(SAMLException.RESPONDER, "General error processing request."));
				}
				return;
			} catch (Exception ee) {
				log.fatal("Could not construct a SAML error response: " + ee);
				throw new ServletException("Attribute Authority response failure.");
			}

		}
	}


}
