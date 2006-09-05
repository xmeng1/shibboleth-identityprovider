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

package edu.internet2.middleware.shibboleth.idp.provider;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;

import javax.security.auth.x500.X500Principal;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.opensaml.NoSuchProviderException;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLBinding;
import org.opensaml.SAMLBindingFactory;
import org.opensaml.SAMLException;
import org.opensaml.SAMLRequest;
import org.opensaml.SAMLResponse;
import org.opensaml.XML;
import org.opensaml.artifact.Artifact;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.security.impl.HttpX509EntityCredential;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.artifact.ArtifactMapping;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolHandler;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolSupport;
import edu.internet2.middleware.shibboleth.idp.RequestHandlingException;

/**
 * @author Walter Hoehn
 */
public class SAMLv1_1ArtifactQueryHandler extends BaseServiceHandler implements IdPProtocolHandler {

	private static Logger log = Logger.getLogger(SAMLv1_1ArtifactQueryHandler.class.getName());
	private SAMLBinding binding;

	public SAMLv1_1ArtifactQueryHandler(Element config) throws ShibbolethConfigurationException {

		super(config);

		try {
			binding = SAMLBindingFactory.getInstance(SAMLBinding.SOAP);
		} catch (NoSuchProviderException e) {
			log.error("Unable to initialize SAML SOAP binding:" + e);
			throw new ShibbolethConfigurationException("Couldn't initialize " + getHandlerName() + " handler.");
		}
	}

	/*
	 * @see edu.internet2.middleware.shibboleth.idp.ProtocolHandler#getHandlerName()
	 */
	public String getHandlerName() {

		return "SAML v1.1 Artifact Query";
	}

	/*
	 * @see edu.internet2.middleware.shibboleth.idp.ProtocolHandler#processRequest(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse, edu.internet2.middleware.shibboleth.idp.ProtocolSupport)
	 */
	public void processRequest(HttpServletRequest request, HttpServletResponse response, IdPProtocolSupport support)
			throws RequestHandlingException, ServletException {

		log.info("Received a request to dereference assertion artifacts.");

		// Parse SOAP request and marshall SAML request object
		SAMLRequest samlRequest = null;
		try {
			samlRequest = binding.receive(request, 1);
		} catch (SAMLException e) {
			log.error("Unable to parse request: " + e);
			throw new RequestHandlingException("Invalid request data.");
		}

		// If we have DEBUG logging turned on, dump out the request to the log
		// This takes some processing, so only do it if we need to
		if (log.isDebugEnabled()) {
			log
					.debug("Dumping generated SAML Request:" + System.getProperty("line.separator")
							+ samlRequest.toString());
		}
		try {

			// Pull credential from request
			X509Certificate[] chain = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
			if (chain == null || chain.length == 0
					|| chain[0].getSubjectX500Principal().getName(X500Principal.RFC2253).equals("")) {
				// The spec says that mutual authentication is required for the
				// artifact profile
				if (samlRequest.isSigned()) {
					log.info("Request is signed, will authenticate it later.");
				} else {
					log.info("Request is from an unauthenticated serviceprovider.");
					throw new SAMLException(SAMLException.REQUESTER,
							"SAML Artifacts cannot be dereferenced for unauthenticated requesters.");
				}
			} else {
				log.info("Request contains TLS credential: ("
						+ chain[0].getSubjectX500Principal().getName(X500Principal.RFC2253) + ").");
			}
			ArrayList<SAMLAssertion> assertions = new ArrayList<SAMLAssertion>();
			Iterator artifacts = samlRequest.getArtifacts();

			if (!artifacts.hasNext()) {
				log.error("Protocol Handler received a SAML Request, but is unable to handle it.  No "
						+ "artifacts were included in the request.");
				throw new SAMLException(SAMLException.REQUESTER, "General error processing request.");
			}

			int queriedArtifacts = 0;
			// for transaction log
			StringBuffer dereferencedArtifacts = new StringBuffer();

			while (artifacts.hasNext()) {
				queriedArtifacts++;
				Artifact artifact = (Artifact) artifacts.next();
				log.info("Dereferencing artifact: (" + artifact.encode() + ").");
				ArtifactMapping mapping = support.getArtifactMapper().recoverAssertion(artifact);

				if (mapping == null) {
					log.info("Could not map artifact to a SAML Assertion.");

				} else if (mapping.isExpired()) {
					log.error("Artifact is expired.  Skipping...");

				} else {
					SAMLAssertion assertion = mapping.getAssertion();
					// See if we have metadata for this provider
					EntityDescriptor provider = null;
					try {
						provider = support.getEntityDescriptor(mapping.getServiceProviderId());
					} catch (MetadataProviderException e) {
						log.error("Metadata lookup for provider (" + mapping.getServiceProviderId()
								+ ") encountered an error: " + e);
					}
					if (provider == null) {
						log.info("No metadata found for provider: (" + mapping.getServiceProviderId() + ").");
						throw new SAMLException(SAMLException.REQUESTER, "Invalid service provider.");
					}
					SPSSODescriptor role = provider.getSPSSODescriptor(XML.SAML11_PROTOCOL_ENUM);
					if (role == null) {
						log.info("SPSSO role not found in metadata for provider: (" + mapping.getServiceProviderId()
								+ ").");
						throw new SAMLException(SAMLException.REQUESTER, "Invalid service provider role.");
					}

					boolean authenticated = false;

					// Make sure that the suppplied credential is valid for the provider to which the artifact was
					// issued
					if (chain != null && chain.length > 0) {
						if (!support.getTrust().validate(new HttpX509EntityCredential(request), role)) {
							log.error("Supplied TLS credential ("
									+ chain[0].getSubjectX500Principal().getName(X500Principal.RFC2253)
									+ ") is NOT valid for provider (" + mapping.getServiceProviderId()
									+ "), to whom this artifact was issued.");
							throw new SAMLException(SAMLException.REQUESTER, "Invalid credential.");
						}
						authenticated = true;
					}
					if (samlRequest.isSigned()) {

						if (!support.getTrust().validate(samlRequest, role)) {
							log.error("Signed SAML request message did NOT contain a valid signature from provider ("
									+ mapping.getServiceProviderId() + "), to whom this artifact was issued.");
							throw new SAMLException(SAMLException.REQUESTER, "Invalid signature.");
						}
						authenticated = true;
					}
					if (!authenticated) {
						log.info("Request could not be authenticated.");
						throw new SAMLException(SAMLException.REQUESTER,
								"SAML Artifacts cannot be dereferenced for unauthenticated requesters.");
					}
					log.debug("Supplied credentials validated for the provider to which this artifact was issued.");
					assertions.add(assertion);
					dereferencedArtifacts.append("(" + artifact.encode() + ")");
				}
			}

			// The spec requires that if any artifacts are dereferenced, they must
			// all be dereferenced
			if (assertions.size() > 0 && assertions.size() != queriedArtifacts) { throw new SAMLException(
					SAMLException.REQUESTER, "Unable to successfully dereference all artifacts."); }

			// Create and send response
			// The spec says that we should send "success" in the case where no artifacts match
			SAMLResponse samlResponse = new SAMLResponse(samlRequest.getId(), null, assertions, null);
			if (log.isDebugEnabled()) {
				log.debug("Dumping generated SAML Response:" + System.getProperty("line.separator")
						+ samlResponse.toString());
			}

			support.getTransactionLog().info(
					"Succesfully dereferenced the following artifacts: " + dereferencedArtifacts.toString());

			binding.respond(response, samlResponse, null);

		} catch (SAMLException e) {

			log.error("Error while processing request: " + e);
			try {
				SAMLResponse samlResponse = new SAMLResponse((samlRequest != null) ? samlRequest.getId() : null, null,
						null, e);
				if (log.isDebugEnabled()) {
					log.debug("Dumping generated SAML Error Response:" + System.getProperty("line.separator")
							+ samlResponse.toString());
				}
				binding.respond(response, samlResponse, null);
				log.debug("Returning SAML Error Response.");
			} catch (SAMLException se) {
				try {
					binding.respond(response, null, e);
				} catch (SAMLException e1) {
					log.error("Caught exception while responding to requester: " + e.getMessage());
					throw new RequestHandlingException(e1.getMessage());
				}
			}
		}
	}

}