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

package edu.internet2.middleware.shibboleth.idp.provider;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;

import javax.security.auth.x500.X500Principal;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLException;
import org.opensaml.SAMLRequest;
import org.opensaml.SAMLResponse;

import sun.misc.BASE64Decoder;
import edu.internet2.middleware.shibboleth.artifact.ArtifactMapper;
import edu.internet2.middleware.shibboleth.artifact.ArtifactMapping;
import edu.internet2.middleware.shibboleth.artifact.provider.MemoryArtifactMapper;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolHandler;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolSupport;
import edu.internet2.middleware.shibboleth.idp.InvalidClientDataException;
import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;

/**
 * @author Walter Hoehn
 */
public class SAMLv1_1ArtifactQueryHandler extends BaseServiceHandler implements IdPProtocolHandler {

	// TODO figure out how to refactor this
	private ArtifactMapper	artifactMapper;

	private static Logger	log	= Logger.getLogger(SAMLv1_1ArtifactQueryHandler.class.getName());

	SAMLv1_1ArtifactQueryHandler() throws ShibbolethConfigurationException {

		artifactMapper = new MemoryArtifactMapper();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see edu.internet2.middleware.shibboleth.idp.ProtocolHandler#getHandlerName()
	 */
	public String getHandlerName() {

		return "SAML v1.1 Artifact Query";
	}

	/*
	 * @see edu.internet2.middleware.shibboleth.idp.ProtocolHandler#processRequest(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse, edu.internet2.middleware.shibboleth.idp.ProtocolSupport)
	 */
	public SAMLResponse processRequest(HttpServletRequest request, HttpServletResponse response,
			SAMLRequest samlRequest, IdPProtocolSupport support) throws SAMLException, InvalidClientDataException,
			IOException, ServletException {

		log.info("Recieved a request to dereference an assertion artifact.");

		// TODO how about signatures on artifact dereferencing
		// Pull credential from request
		X509Certificate credential = getCredentialFromProvider(request);
		if (credential == null || credential.getSubjectX500Principal().getName(X500Principal.RFC2253).equals("")) {
			// The spec says that mutual authentication is required for the
			// artifact profile
			log.info("Request is from an unauthenticated serviceprovider.");
			throw new SAMLException(SAMLException.REQUESTER,
					"SAML Artifacts cannot be dereferenced for unauthenticated requesters.");
		}
		log.info("Request contains credential: (" + credential.getSubjectX500Principal().getName(X500Principal.RFC2253)
				+ ").");
		ArrayList assertions = new ArrayList();
		Iterator artifacts = samlRequest.getArtifacts();

		// TODO error if not artifacts

		int queriedArtifacts = 0;
		StringBuffer dereferencedArtifacts = new StringBuffer();
		// for // transaction // log
		while (artifacts.hasNext()) {
			queriedArtifacts++;
			String artifact = (String) artifacts.next();
			log.debug("Attempting to dereference artifact: (" + artifact + ").");
			ArtifactMapping mapping = artifactMapper.recoverAssertion(artifact);
			if (mapping != null) {
				SAMLAssertion assertion = mapping.getAssertion(); // See if we have metadata for this provider
				EntityDescriptor provider = support.lookup(mapping.getServiceProviderId());
				if (provider == null) {
					log.info("No metadata found for provider: (" + mapping.getServiceProviderId() + ").");
					throw new SAMLException(SAMLException.REQUESTER, "Invalid service provider.");
				}
				// Make sure that the suppplied credential is valid for the // provider to which theartifact was issued
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
		} // The spec requires that if any artifacts are dereferenced, they must
		// all be dereferenced
		if (assertions.size() > 0 && assertions.size() != queriedArtifacts) { throw new SAMLException(
				SAMLException.REQUESTER, "Unable to successfully dereference all artifacts."); }
		// Create and send response
		// The spec says that we should send "success" in the case where no // artifacts match
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

		support.getTransactionLog().info(
				"Succesfully dereferenced the following artifacts: " + dereferencedArtifacts.toString());
		return samlResponse;
	}

}