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

package edu.internet2.middleware.shibboleth.shire;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.UnavailableException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpUtils;

import org.apache.log4j.Logger;
import org.doomdark.uuid.UUIDGenerator;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLException;
import org.opensaml.SAMLResponse;

import edu.internet2.middleware.shibboleth.common.Constants;
import edu.internet2.middleware.shibboleth.common.OriginSiteMapperException;
import edu.internet2.middleware.shibboleth.common.ShibPOSTProfile;
import edu.internet2.middleware.shibboleth.common.ShibPOSTProfileFactory;

/**
 *  Implements a SAML POST profile consumer
 *
 * @author     Scott Cantor
 * @created    June 10, 2002
 */

public class ShireServlet extends HttpServlet {

	private String shireLocation;
	private String cookieName;
	private String cookieDomain;
	private String sessionDir;
	private String keyStorePath;
	private String keyStorePasswd;
	private String keyStoreAlias;
	private String registryURI;
	private boolean sslOnly = true;
	private boolean checkAddress = true;
	private boolean verbose = false;

	private XMLOriginSiteMapper mapper = null;
	private static Logger log = Logger.getLogger(ShireServlet.class.getName());

	/**
	 *  Use the following servlet init parameters:<P>
	 *
	 *
	 *  <DL>
	 *    <DT> shire-location <I>(optional)</I> </DT>
	 *    <DD> The URL of the SHIRE if not derivable from requests</DD>
	 *    <DT> keystore-path <I>(required)</I> </DT>
	 *    <DD> A pathname to the trusted CA roots to accept</DD>
	 *    <DT> keystore-password <I>(required)</I> </DT>
	 *    <DD> The root keystore password</DD>
	 *    <DT> registry-alias <I>(optional)</I> </DT>
	 *    <DD> An alias in the provided keystore for the cert that can verify
	 *    the origin site registry signature</DD>
	 *    <DT> registry-uri <I>(required)</I> </DT>
	 *    <DD> The origin site registry URI to install</DD>
	 *    <DT> cookie-name <I>(required)</I> </DT>
	 *    <DD> Name of session cookie to set in browser</DD>
	 *    <DT> cookie-domain <I>(optional)</I> </DT>
	 *    <DD> Domain of session cookie to set in browser</DD>
	 *    <DT> ssl-only <I>(defaults to true)</I> </DT>
	 *    <DD> If true, allow only SSL-protected POSTs and issue a secure cookie
	 *    </DD>
	 *    <DT> check-address <I>(defaults to true)</I> </DT>
	 *    <DD> If true, check client's IP address against assertion</DD>
	 *    <DT> session-dir <I>(defaults to /tmp)</I> </DT>
	 *    <DD> Directory in which to place session files</DD>
	 *  </DL>
	 *
	 */
	public void init() throws ServletException {
		super.init();
		log.info("Initializing SHIRE.");

		edu.internet2.middleware.shibboleth.common.Init.init();

		loadInitParams();
		verifyConfig();

		log.info("Loading keystore.");
		try {
			Key k = null;
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(getServletContext().getResourceAsStream(keyStorePath), keyStorePasswd.toCharArray());

			if (keyStoreAlias != null) {
				Certificate cert;
				cert = ks.getCertificate(keyStoreAlias);

				if (cert == null || (k = cert.getPublicKey()) == null) {
					log.fatal(
						"Unable to load registry verification certificate ("
							+ keyStoreAlias
							+ ") from keystore");
					throw new UnavailableException(
						"Unable to load registry verification certificate ("
							+ keyStoreAlias
							+ ") from keystore");
				}
			}

			log.info("Loading shibboleth site information.");
			mapper = new XMLOriginSiteMapper(registryURI, k, ks);
			log.info("Completed SHIRE initialization");

		} catch (OriginSiteMapperException e) {
			log.fatal("Unable load shibboleth site information." + e);
			throw new UnavailableException("Unable load shibboleth site information." + e);
		} catch (KeyStoreException e) {
			log.fatal("Unable supplied keystore." + e);
			throw new UnavailableException("Unable load supplied keystore." + e);
		} catch (NoSuchAlgorithmException e) {
			log.fatal("Unable supplied keystore." + e);
			throw new UnavailableException("Unable load supplied keystore." + e);
		} catch (CertificateException e) {
			log.fatal("Unable supplied keystore." + e);
			throw new UnavailableException("Unable load supplied keystore." + e);
		} catch (IOException e) {
			log.fatal("Unable supplied keystore." + e);
			throw new UnavailableException("Unable load supplied keystore." + e);
		}

	}

	/**
	 * Ensures that all required initialization attributes have been set.
	 */
	private void verifyConfig() throws UnavailableException {

		if (cookieName == null) {
			log.fatal("Init parameter (cookie-name) is required in deployment descriptor.");
			throw new UnavailableException("Init parameter (cookie-name) is required in deployment descriptor.");
		}

		if (registryURI == null) {
			log.fatal("Init parameter (registry-uri) is required in deployment descriptor.");
			throw new UnavailableException("Init parameter (registry-uri) is required in deployment descriptor.");
		}

		if (keyStorePath == null) {
			log.fatal("Init parameter (keystore-path) is required in deployment descriptor.");
			throw new UnavailableException("Init parameter (keystore-path) is required in deployment descriptor.");
		}

		if (keyStorePasswd == null) {
			log.fatal("Init parameter (keystore-password) is required in deployment descriptor.");
			throw new UnavailableException("Init parameter (keystore-password) is required in deployment descriptor.");
		}

	}

	/**
	 * Loads SHIRE configuration parameters.  Sets default values as appropriate.
	 */
	private void loadInitParams() {

		log.info("Loading configuration from deployment descriptor (web.xml).");

		shireLocation = getServletConfig().getInitParameter("shire-location");
		cookieDomain = getServletConfig().getInitParameter("cookie-domain");
		cookieName = getServletConfig().getInitParameter("cookie-name");
		keyStorePath = getServletConfig().getInitParameter("keystore-path");
		keyStorePasswd = getServletConfig().getInitParameter("keystore-password");
		keyStoreAlias = getServletConfig().getInitParameter("keystore-alias");
		registryURI = getServletConfig().getInitParameter("registry-uri");

		sessionDir = getServletConfig().getInitParameter("session-dir");
		if (sessionDir == null) {
			sessionDir = "/tmp";
			log.warn("No session-dir parameter found... using default location: (" + sessionDir + ").");
		}

		String temp = getServletConfig().getInitParameter("ssl-only");
		if (temp != null && (temp.equalsIgnoreCase("false") || temp.equals("0")))
			sslOnly = false;

		temp = getServletConfig().getInitParameter("check-address");
		if (temp != null && (temp.equalsIgnoreCase("false") || temp.equals("0")))
			checkAddress = false;

	}

	/**
	 *  Processes a sign-on submission<P>
	 *
	 *
	 *
	 * @param  request               HTTP request context
	 * @param  response              HTTP response context
	 * @exception  IOException       Thrown if an I/O error occurs
	 * @exception  ServletException  Thrown if a servlet engine error occurs
	 */
	public void doPost(HttpServletRequest request, HttpServletResponse response)
		throws IOException, ServletException {

		try {

			log.info("Received a handle package.");
			log.debug("Target URL from client: " + request.getParameter("TARGET"));
			validateRequest(request);

			SAMLAuthenticationStatement s = processAssertion(request);
			shareSession(
				response,
				s.getSubject().getName(),
				s.getSubject().getNameQualifier(),
				System.currentTimeMillis(),
				request.getRemoteAddr(),
				s.getBindings()[0].getBinding(),
				s.getBindings()[0].getLocation());

			log.info("Redirecting to the requested resource.");
			response.sendRedirect(request.getParameter("TARGET"));

		} catch (ShireException se) {
			handleError(se, request, response);
		}

	}

	/**
	 * Extracts a SAML Authentication Assertion from a POST request object and performs appropriate validity 
	 * checks on the same. 
	 *
	 * @param  request The <code>HttpServletRequest</code> object for the current request
	 * @exception  ShireException  Thrown if any error is encountered parsing or validating the assertion 
	 * that is retreived from the request object.
	 */

	private SAMLAuthenticationStatement processAssertion(HttpServletRequest request) throws ShireException {

		log.info("Processing SAML Assertion.");
		try {
			// Get a profile object using our specifics.
			String[] policies = { Constants.POLICY_CLUBSHIB };
			ShibPOSTProfile profile =
				ShibPOSTProfileFactory.getInstance(
					policies,
					mapper,
					(shireLocation != null) ? shireLocation : HttpUtils.getRequestURL(request).toString(),
					300);

			// Try and accept the response...
			SAMLResponse r = profile.accept(request.getParameter("SAMLResponse").getBytes());

			// We've got a valid signed response we can trust (or the whole response was empty...)

			ByteArrayOutputStream bytestr = new ByteArrayOutputStream();
			try {
				r.toStream(bytestr);
			} catch (IOException e) {
				log.error(
					"Very Strange... problem converting SAMLResponse to a Stream for logging purposes.");
			}

			log.debug("Parsed SAML Response: " + bytestr.toString());

			// Get the statement we need.
			SAMLAuthenticationStatement s = profile.getSSOStatement(r);
			if (s == null) {
				throw new ShireException("The assertion of your Shibboleth identity was missing or incompatible with the policies of this site.");
			}

			if (checkAddress) {
				log.debug("Running with client address checking enabled.");
				log.debug("Client Address from request: " + request.getRemoteAddr());
				log.debug("Client Address from assertion: " + s.getSubjectIP());
				if (s.getSubjectIP() == null || !s.getSubjectIP().equals(request.getRemoteAddr())) {
					throw new ShireException("The IP address provided by your origin site was either missing or did not match your current address.  To correct this problem, you may need to bypass a local proxy server.");
				}
			}

			// All we really need is here...
			log.debug("Shibboleth Origin Site: " + s.getSubject().getNameQualifier());
			log.debug("Shibboleth Handle: " + s.getSubject().getName());
			log.debug("Shibboleth AA URL:</B>" + s.getBindings()[0].getLocation());
			return s;

		} catch (SAMLException e) {
			throw new ShireException("Error processing SAML assertion: " + e);
		}
	}

	/**
	 * Makes user information available to SHAR.
	 * 
	 */

	private void shareSession(
		HttpServletResponse response,
		String handle,
		String domain,
		long currentTime,
		String clientAddress,
		String protocolBinding,
		String locationBinding)
		throws ShireException {

		log.info("Generating SHIR/SHAR shared data.");
		String filename = UUIDGenerator.getInstance().generateRandomBasedUUID().toString();
		log.debug("Created unique session identifier: " + filename);

		// Write session identifier to a file		
		String pathname = null;
		if (sessionDir.endsWith(File.separator))
			pathname = sessionDir + filename;
		else
			pathname = sessionDir + File.separatorChar + filename;
		PrintWriter fout;
		try {
			log.debug("Writing session data to file: (" + pathname + ")");
			fout = new PrintWriter(new FileWriter(pathname));

			log.debug("Session Pathname: " + pathname);

			fout.println("Handle=" + handle);
			fout.println("Domain=" + domain);
			fout.println("PBinding0=" + protocolBinding);
			fout.println("LBinding0=" + locationBinding);
			fout.println("Time=" + currentTime / 1000);
			fout.println("ClientAddress=" + clientAddress);
			fout.println("EOF");
			fout.close();

			Cookie cookie = new Cookie(cookieName, filename);
			cookie.setPath("/");
			if (cookieDomain != null)
				cookie.setDomain(cookieDomain);
			log.debug(
				"Adding session identifier to browser cookie: ("
					+ cookie.getDomain()
					+ ":"
					+ cookie.getName()
					+ ")");
			response.addCookie(cookie);

		} catch (IOException e) {
			throw new ShireException(
				"Unable to write session to file (" + filename + ") : " + e);
		}
	}

	/**
	 * Ensures that the POST request contains the necessary data elements
	 * 
	 * @param request <code>The HttpServletRequest</code> object for the current request
	 * @exception ShireException thrown if required POST data is missing
	 */

	private void validateRequest(HttpServletRequest request) throws ShireException {

		log.info("Validating POST request properties.");

		if (sslOnly && !request.isSecure()) {
			throw new ShireException("Access to this site requires the use of SSL.");
		}

		if (request.getParameter("TARGET") == null || request.getParameter("TARGET").length() == 0) {
			throw new ShireException("Invalid data from HS: No target URL received.");
		}

		if (request.getParameter("SAMLResponse") == null
			|| request.getParameter("SAMLResponse").length() == 0) {
			throw new ShireException("Invalid data from HS: No SAML Assertion included received.");
		}

	}

	/**
	 * Appropriately routes all recoverable errors encountered by the SHIRE
	 */

	private void handleError(ShireException se, HttpServletRequest req, HttpServletResponse res) {
		log.error(se);
		log.debug("Displaying error page.");
		req.setAttribute("errorText", se.toString());
		req.setAttribute("requestURL", req.getRequestURI().toString());
		RequestDispatcher rd = req.getRequestDispatcher("/wayferror.jsp");

		try {
			rd.forward(req, res);
		} catch (IOException ioe) {
			log.error("Problem trying to display SHIRE error page: " + ioe.toString());
		} catch (ServletException servletE) {
			log.error("Problem trying to display SHIRE error page: " + servletE.toString());
		}
	}
}
