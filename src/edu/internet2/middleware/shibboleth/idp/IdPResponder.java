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
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.security.auth.x500.X500Principal;
import javax.servlet.ServletException;
import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAttributeQuery;
import org.opensaml.SAMLBinding;
import org.opensaml.SAMLException;
import org.opensaml.SAMLIdentifier;
import org.opensaml.SAMLRequest;
import org.opensaml.SAMLResponse;

import sun.misc.BASE64Decoder;

import edu.internet2.middleware.shibboleth.common.SAMLBindingFactory;
import edu.internet2.middleware.shibboleth.common.ServiceProvider;
import edu.internet2.middleware.shibboleth.common.ShibPOSTProfile;
import edu.internet2.middleware.shibboleth.common.TargetFederationComponent;
import edu.internet2.middleware.shibboleth.hs.HSRelyingParty;
import edu.internet2.middleware.shibboleth.metadata.AttributeConsumerRole;
import edu.internet2.middleware.shibboleth.metadata.KeyDescriptor;
import edu.internet2.middleware.shibboleth.metadata.Provider;
import edu.internet2.middleware.shibboleth.metadata.ProviderRole;

/**
 * Primary entrypoint for requests to the SAML IdP. Listens on multiple endpoints, routes requests to the appropriate
 * IdP processing components, and delivers proper protocol responses.
 * 
 * @author Walter Hoehn
 */

public class IdPResponder extends TargetFederationComponent {

	private static Logger		transactionLog	= Logger.getLogger("Shibboleth-TRANSACTION");
	private static Logger		log				= Logger.getLogger(IdPResponder.class.getName());
	private SAMLBinding			binding;
	private ArtifactRepository	artifactRepository;

	public void init() throws ServletException {

		super.init();
		MDC.put("serviceId", "[IdP] Core");
		log.info("Initializing Identity Provider.");

		try {
			binding = SAMLBindingFactory.getInstance(SAMLBinding.SAML_SOAP_HTTPS);
			log.info("Identity Provider initialization complete.");

		} catch (SAMLException se) {
			log.fatal("SAML SOAP binding could not be loaded: " + se);
			throw new UnavailableException("Identity Provider failed to initialize.");
		}
	}

	public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

		MDC.put("serviceId", "[IdP] " + new SAMLIdentifier().toString());
		MDC.put("remoteAddr", request.getRemoteAddr());
		log.debug("Recieved a request via POST.");

		// Parse SOAP request and marshall SAML request object
		try {
			SAMLRequest samlRequest = null;
			try {
				samlRequest = binding.receive(request);
			} catch (SAMLException e) {
				log.fatal("Unable to parse request: " + e);
				throw new SAMLException("Invalid request data.");
			}

			// Determine the request type
			Iterator artifacts = samlRequest.getArtifacts();
			if (artifacts.hasNext()) {
				log.info("Recieved a request to dereference an assertion artifact.");
				processArtifactDereference(samlRequest, request, response);
				return;
			}

			if (samlRequest.getQuery() != null && (samlRequest.getQuery() instanceof SAMLAttributeQuery)) {
				log.info("Recieved an attribute query.");
				processAttributeQuery(samlRequest, request, response);
				return;
			}

			throw new SAMLException(SAMLException.REQUESTER,
					"Identity Provider unable to respond to this SAML Request type.");

		} catch (SAMLException e) {
			// TODO handle properly, like in the AA stuff
		}
	}

	private void processAttributeQuery(SAMLRequest samlRequest, HttpServletRequest request, HttpServletResponse response) {
	//TODO validate that the endpoint is valid for the request type
	//TODO implement
	}

	private void processArtifactDereference(SAMLRequest samlRequest, HttpServletRequest request,
			HttpServletResponse response) throws SAMLException, IOException {
		//TODO validate that the endpoint is valid for the request type

		// Pull credential from request
		X509Certificate credential = getCredentialFromProvider(request);
		if (credential == null || credential.getSubjectX500Principal().getName(X500Principal.RFC2253).equals("")) {
			log.info("Request is from an unauthenticated service provider.");
			throw new SAMLException(SAMLException.REQUESTER,
					"SAML Artifacts cannot be dereferenced for unauthenticated requesters.");
		}

		log.info("Request contains credential: (" + credential.getSubjectX500Principal().getName(X500Principal.RFC2253)
				+ ").");

		ArrayList assertions = new ArrayList();
		Iterator artifacts = samlRequest.getArtifacts();

		int queriedArtifacts = 0;
		StringBuffer dereferencedArtifacts = new StringBuffer(); //for transaction log
		while (artifacts.hasNext()) {
			queriedArtifacts++;
			String artifact = (String) artifacts.next();
			log.debug("Attempting to dereference artifact: (" + artifact + ").");
			ArtifactMapping mapping = artifactRepository.recoverAssertion(artifact);
			if (mapping != null) {
				SAMLAssertion assertion = mapping.getAssertion();

				//See if we have metadata for this provider
				Provider provider = lookup(mapping.getServiceProviderId());
				if (provider == null) {
					log.info("No metadata found for provider: (" + mapping.getServiceProviderId() + ").");
					throw new SAMLException(SAMLException.REQUESTER, "Invalid service provider.");
				}

				//Make sure that the suppplied credential is valid for the provider to which the artifact was issued
				if (!isValidCredential(provider, credential)) {
					log.error("Supplied credential ("
							+ credential.getSubjectX500Principal().getName(X500Principal.RFC2253)
							+ ") is NOT valid for provider (" + mapping.getServiceProviderId()
							+ "), to whom this artifact was issued.");
					throw new SAMLException(SAMLException.REQUESTER, "Invalid credential.");
				}

				log.debug("Supplied credential validated for the provider to which this artifact was issued.");

				assertions.add(assertion);
				dereferencedArtifacts.append("(" + artifact + ")");
			}
		}

		//The spec requires that if any artifacts are dereferenced, they must all be dereferenced
		if (assertions.size() > 0 & assertions.size() != queriedArtifacts) { throw new SAMLException(
				SAMLException.REQUESTER, "Unable to successfully dereference all artifacts."); }

		//Create and send response
		SAMLResponse samlResponse = new SAMLResponse(samlRequest.getId(), null, assertions, null);

		if (log.isDebugEnabled()) {
			try {
				log.debug("Dumping generated SAML Response:"
						+ System.getProperty("line.separator")
						+ new String(new BASE64Decoder().decodeBuffer(new String(samlResponse.toBase64(), "ASCII")),
								"UTF8"));
			} catch (SAMLException e) {
				log.error("Encountered an error while decoding SAMLReponse for logging purposes.");
			} catch (IOException e) {
				log.error("Encountered an error while decoding SAMLReponse for logging purposes.");
			}
		}

		binding.respond(response, samlResponse, null);

		transactionLog.info("Succesfully dereferenced the following artifacts: " + dereferencedArtifacts.toString());
		/*
		 * } catch (Exception e) { log.error("Error while processing request: " + e); try { sendFailure(res,
		 * samlRequest, new SAMLException(SAMLException.RESPONDER, "General error processing request.")); return; }
		 * catch (Exception ee) { log.fatal("Could not construct a SAML error response: " + ee); throw new
		 * ServletException("Handle Service response failure."); } }
		 */
	}

	public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

		MDC.put("serviceId", "[IdP] " + new SAMLIdentifier().toString());
		MDC.put("remoteAddr", request.getRemoteAddr());
		log.debug("Recieved a request via GET.");
	}

	private X509Certificate getCredentialFromProvider(HttpServletRequest req) {
		X509Certificate[] certArray = (X509Certificate[]) req.getAttribute("javax.servlet.request.X509Certificate");
		if (certArray != null && certArray.length > 0) { return certArray[0]; }
		return null;
	}

	private boolean isValidCredential(Provider provider, X509Certificate certificate) {

		ProviderRole[] roles = provider.getRoles();
		if (roles.length == 0) {
			log.info("Inappropriate metadata for provider.");
			return false;
		}
		//TODO figure out what to do about this role business here
		for (int i = 0; roles.length > i; i++) {
			if (roles[i] instanceof AttributeConsumerRole) {
				KeyDescriptor[] descriptors = roles[i].getKeyDescriptors();
				for (int j = 0; descriptors.length > j; j++) {
					KeyInfo[] keyInfo = descriptors[j].getKeyInfo();
					for (int k = 0; keyInfo.length > k; k++) {
						for (int l = 0; keyInfo[k].lengthKeyName() > l; l++) {
							try {

								//First, try to match DN against metadata
								try {
									if (certificate.getSubjectX500Principal().getName(X500Principal.RFC2253).equals(
											new X500Principal(keyInfo[k].itemKeyName(l).getKeyName())
													.getName(X500Principal.RFC2253))) {
										log.debug("Matched against DN.");
										return true;
									}
								} catch (IllegalArgumentException iae) {
									//squelch this runtime exception, since this might be a valid case
								}

								//If that doesn't work, we try matching against some Subject Alt Names
								try {
									Collection altNames = certificate.getSubjectAlternativeNames();
									if (altNames != null) {
										for (Iterator nameIterator = altNames.iterator(); nameIterator.hasNext();) {
											List altName = (List) nameIterator.next();
											if (altName.get(0).equals(new Integer(2))
													|| altName.get(0).equals(new Integer(6))) { //2 is DNS, 6 is URI
												if (altName.get(1).equals(keyInfo[k].itemKeyName(l).getKeyName())) {
													log.debug("Matched against SubjectAltName.");
													return true;
												}
											}
										}
									}
								} catch (CertificateParsingException e1) {
									log
											.error("Encountered an problem trying to extract Subject Alternate Name from supplied certificate: "
													+ e1);
								}

								//If that doesn't work, try to match using SSL-style hostname matching
								if (ShibPOSTProfile.getHostNameFromDN(certificate.getSubjectX500Principal()).equals(
										keyInfo[k].itemKeyName(l).getKeyName())) {
									log.debug("Matched against hostname.");
									return true;
								}

							} catch (XMLSecurityException e) {
								log.error("Encountered an error reading federation metadata: " + e);
							}
						}
					}
				}
			}
		}
		log.info("Supplied credential not found in metadata.");
		return false;
	}

	abstract class ArtifactRepository {

		// TODO figure out what to do about this interface long term
		abstract String addAssertion(SAMLAssertion assertion, HSRelyingParty relyingParty);

		abstract ArtifactMapping recoverAssertion(String artifact);
	}

	class ArtifactMapping {

		//TODO figure out what to do about this interface long term
		private String			assertionHandle;
		private long			expirationTime;
		private SAMLAssertion	assertion;
		private String			serviceProviderId;

		ArtifactMapping(String assertionHandle, SAMLAssertion assertion, ServiceProvider sp) {
			this.assertionHandle = assertionHandle;
			this.assertion = assertion;
			expirationTime = System.currentTimeMillis() + (1000 * 60 * 5); //in 5 minutes
			serviceProviderId = sp.getProviderId();
		}

		boolean isExpired() {
			if (System.currentTimeMillis() > expirationTime) { return true; }
			return false;
		}

		boolean isCorrectProvider(ServiceProvider sp) {
			if (sp.getProviderId().equals(serviceProviderId)) { return true; }
			return false;
		}

		SAMLAssertion getAssertion() {
			return assertion;
		}

		String getServiceProviderId() {
			return serviceProviderId;
		}
	}
}