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

package edu.internet2.middleware.shibboleth.hs;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Properties;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.doomdark.uuid.UUIDGenerator;
import org.opensaml.QName;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLAuthorityBinding;
import org.opensaml.SAMLBinding;
import org.opensaml.SAMLException;
import org.opensaml.SAMLResponse;

import sun.misc.BASE64Decoder;
import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;
import edu.internet2.middleware.shibboleth.common.ShibPOSTProfile;
import edu.internet2.middleware.shibboleth.common.ShibPOSTProfileFactory;
import edu.internet2.middleware.shibboleth.common.ShibResource;

public class HandleServlet extends HttpServlet {

	protected Properties configuration;
	protected HandleRepository handleRepository;
	protected ShibPOSTProfile postProfile;
	private static Logger log = Logger.getLogger(HandleServlet.class.getName());
	private Certificate[] certificates;
	private PrivateKey privateKey;
	protected Properties loadConfiguration() throws HSConfigurationException {

		//Set defaults
		Properties defaultProps = new Properties();
		defaultProps.setProperty("edu.internet2.middleware.shibboleth.hs.HandleServlet.username", "REMOTE_USER");
		defaultProps.setProperty(
			"edu.internet2.middleware.shibboleth.hs.HandleRepository.implementation",
			"edu.internet2.middleware.shibboleth.hs.provider.MemoryHandleRepository");
		defaultProps.setProperty("edu.internet2.middleware.shibboleth.hs.BaseHandleRepository.handleTTL", "1800000");
		defaultProps.setProperty(
			"edu.internet2.middleware.shibboleth.hs.provider.CryptoHandleRepository.keyStorePath",
			"/conf/handle.jks");
		defaultProps.setProperty("edu.internet2.middleware.shibboleth.audiences", "urn:mace:InCommon:pilot:2003");
		defaultProps.setProperty(
			"edu.internet2.middleware.shibboleth.hs.HandleServlet.authMethod",
			SAMLAuthenticationStatement.AuthenticationMethod_Unspecified);

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
					"edu.internet2.middleware.shibboleth.hs.HandleServlet.issuer",
					"edu.internet2.middleware.shibboleth.hs.HandleServlet.authenticationDomain",
					"edu.internet2.middleware.shibboleth.hs.HandleServlet.AAUrl",
					"edu.internet2.middleware.shibboleth.hs.HandleServlet.keyStorePath",
					"edu.internet2.middleware.shibboleth.hs.HandleServlet.keyStorePassword",
					"edu.internet2.middleware.shibboleth.hs.HandleServlet.keyStoreKeyAlias",
					"edu.internet2.middleware.shibboleth.hs.HandleServlet.keyStoreKeyPassword",
					"edu.internet2.middleware.shibboleth.hs.HandleServlet.authMethod",
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
				throw new HSConfigurationException("Missing configuration data.");
			}

		} catch (IOException e) {
			log.error("Could not load HS servlet configuration: " + e);
			throw new HSConfigurationException("Could not load HS servlet configuration.");
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

	public void init() throws ServletException {
		super.init();
		MDC.put("serviceId", "[HS] Core");
		try {
			log.info("Initializing Handle Service.");
			configuration = loadConfiguration();

			initPKI();

			postProfile =
				ShibPOSTProfileFactory.getInstance(
					Arrays.asList(
						configuration.getProperty("edu.internet2.middleware.shibboleth.audiences").replaceAll(
							"\\s",
							"").split(
							",")),
					configuration.getProperty("edu.internet2.middleware.shibboleth.hs.HandleServlet.issuer"));

			handleRepository = HandleRepositoryFactory.getInstance(configuration);
			log.info("Handle Service initialization complete.");

		} catch (SAMLException ex) {
			log.fatal("Error initializing SAML libraries: " + ex);
			throw new UnavailableException("Handle Service failed to initialize.");
		} catch (HSConfigurationException ex) {
			log.fatal("Handle Service runtime configuration error.  Please fix and re-initialize. Cause: " + ex);
			throw new UnavailableException("Handle Service failed to initialize.");
		} catch (HandleRepositoryException ex) {
			log.fatal("Unable to load Handle Repository: " + ex);
			throw new UnavailableException("Handle Service failed to initialize.");
		}
	}

	protected void initPKI() throws HSConfigurationException {
		try {
			KeyStore keyStore = KeyStore.getInstance("JKS");

			keyStore.load(
				new ShibResource(
					configuration.getProperty("edu.internet2.middleware.shibboleth.hs.HandleServlet.keyStorePath"),
					this.getClass())
					.getInputStream(),
				configuration
					.getProperty("edu.internet2.middleware.shibboleth.hs.HandleServlet.keyStorePassword")
					.toCharArray());

			privateKey =
				(PrivateKey) keyStore.getKey(
					configuration.getProperty("edu.internet2.middleware.shibboleth.hs.HandleServlet.keyStoreKeyAlias"),
					configuration
						.getProperty("edu.internet2.middleware.shibboleth.hs.HandleServlet.keyStoreKeyPassword")
						.toCharArray());

			if (configuration.getProperty("edu.internet2.middleware.shibboleth.hs.HandleServlet.certAlias") != null) {
				certificates =
					keyStore.getCertificateChain(
						configuration.getProperty("edu.internet2.middleware.shibboleth.hs.HandleServlet.certAlias"));
				if (certificates == null) {
					throw new HSConfigurationException(
						"An error occurred while reading the java keystore: No certificate found with the specified alias ("
							+ configuration.getProperty("edu.internet2.middleware.shibboleth.hs.HandleServlet.certAlias")
							+ ").");
				}
			} else {
				certificates =
					keyStore.getCertificateChain(
						configuration.getProperty(
							"edu.internet2.middleware.shibboleth.hs.HandleServlet.keyStoreKeyAlias"));
				if (certificates == null) {
					throw new HSConfigurationException(
						"An error occurred while reading the java keystore: No certificate found with the specified alias ("
							+ configuration.getProperty(
								"edu.internet2.middleware.shibboleth.hs.HandleServlet.keyStoreKeyAlias")
							+ ").");
				}
			}

		} catch (KeyStoreException e) {
			throw new HSConfigurationException("An error occurred while accessing the java keystore: " + e);
		} catch (NoSuchAlgorithmException e) {
			throw new HSConfigurationException("Appropriate JCE provider not found in the java environment: " + e);
		} catch (CertificateException e) {
			throw new HSConfigurationException(
				"The java keystore contained a certificate that could not be loaded: " + e);
		} catch (IOException e) {
			throw new HSConfigurationException("An error occurred while reading the java keystore: " + e);
		} catch (UnrecoverableKeyException e) {
			throw new HSConfigurationException(
				"An error occurred while attempting to load the key from the java keystore: " + e);
		}
	}
	public void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {

		MDC.put("serviceId", "[HS] " + UUIDGenerator.getInstance().generateRandomBasedUUID());
		MDC.put("remoteAddr", req.getRemoteAddr());
		log.info("Handling request.");

		try {
			checkRequestParams(req);

			req.setAttribute("shire", req.getParameter("shire"));
			req.setAttribute("target", req.getParameter("target"));

			String header = configuration.getProperty("edu.internet2.middleware.shibboleth.hs.HandleServlet.username");
			String username = header.equalsIgnoreCase("REMOTE_USER") ? req.getRemoteUser() : req.getHeader(header);

			String handle = handleRepository.getHandle(new AuthNPrincipal(username));
			log.info("Issued Handle (" + handle + ") to (" + username + ")");

			byte[] buf =
				generateAssertion(
					handle,
					req.getParameter("shire"),
					req.getRemoteAddr(),
					configuration.getProperty("edu.internet2.middleware.shibboleth.hs.HandleServlet.authMethod"));

			createForm(req, res, buf);

		} catch (HandleRepositoryException ex) {
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
		}

	}

	protected byte[] generateAssertion(String handle, String shireURL, String clientAddress, String authType)
		throws SAMLException, IOException {

		SAMLAuthorityBinding binding =
			new SAMLAuthorityBinding(
				SAMLBinding.SAML_SOAP_HTTPS,
				configuration.getProperty("edu.internet2.middleware.shibboleth.hs.HandleServlet.AAUrl"),
				new QName(org.opensaml.XML.SAMLP_NS, "AttributeQuery"));

		SAMLResponse r =
			postProfile.prepare(
				shireURL,
				handle,
				configuration.getProperty("edu.internet2.middleware.shibboleth.hs.HandleServlet.authenticationDomain"),
				clientAddress,
				authType,
				new Date(System.currentTimeMillis()),
				Collections.singleton(binding),
				privateKey,
				Arrays.asList(certificates),
				null,
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
}


    

