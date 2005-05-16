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
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;

import javax.security.auth.x500.X500Principal;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLAttributeDesignator;
import org.opensaml.SAMLAttributeQuery;
import org.opensaml.SAMLAttributeStatement;
import org.opensaml.SAMLAudienceRestrictionCondition;
import org.opensaml.SAMLCondition;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
import org.opensaml.SAMLRequest;
import org.opensaml.SAMLResponse;
import org.opensaml.SAMLStatement;
import org.opensaml.SAMLSubject;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.AAException;
import edu.internet2.middleware.shibboleth.common.InvalidNameIdentifierException;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMapping;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMappingException;
import edu.internet2.middleware.shibboleth.common.RelyingParty;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolHandler;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolSupport;
import edu.internet2.middleware.shibboleth.metadata.AttributeRequesterDescriptor;
import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;
import edu.internet2.middleware.shibboleth.metadata.RoleDescriptor;
import edu.internet2.middleware.shibboleth.metadata.SPSSODescriptor;

/**
 * @author Walter Hoehn
 */
public class SAMLv1_AttributeQueryHandler extends BaseServiceHandler implements IdPProtocolHandler {

	private static Logger log = Logger.getLogger(SAMLv1_AttributeQueryHandler.class.getName());

	/**
	 * Required DOM-based constructor.
	 */
	public SAMLv1_AttributeQueryHandler(Element config) throws ShibbolethConfigurationException {

		super(config);
	}

	/*
	 * @see edu.internet2.middleware.shibboleth.idp.ProtocolHandler#getHandlerName()
	 */
	public String getHandlerName() {

		return "SAML v1.1 Attribute Query";
	}

	private String getEffectiveName(HttpServletRequest req, RelyingParty relyingParty, IdPProtocolSupport support)
			throws InvalidProviderCredentialException {

		X509Certificate credential = getCredentialFromProvider(req);

		if (credential == null || credential.getSubjectX500Principal().getName(X500Principal.RFC2253).equals("")) {
			log.info("Request is from an unauthenticated service provider.");
			return null;

		} else {
			log.info("Request contains credential: ("
					+ credential.getSubjectX500Principal().getName(X500Principal.RFC2253) + ").");
			// Mockup old requester name for requests from < 1.2 SPs
			if (fromLegacyProvider(req)) {
				String legacyName = getHostNameFromDN(credential.getSubjectX500Principal());
				if (legacyName == null) {
					log.error("Unable to extract legacy requester name from certificate subject.");
				}

				log.info("Request from legacy service provider: (" + legacyName + ").");
				return legacyName;

			} else {

				// See if we have metadata for this provider
				EntityDescriptor provider = support.lookup(relyingParty.getProviderId());
				if (provider == null) {
					log.info("No metadata found for provider: (" + relyingParty.getProviderId() + ").");
					log.info("Treating remote provider as unauthenticated.");
					return null;
				}
                RoleDescriptor ar_role = provider.getAttributeRequesterDescriptor("urn:oasis:names:tc:SAML:1.1:protocol");
				RoleDescriptor sp_role = provider.getSPSSODescriptor("urn:oasis:names:tc:SAML:1.1:protocol");
				if (ar_role == null && sp_role == null) {
					log.info("SPSSO and Stand-Alone Requester roles not found in metadata for provider: (" + relyingParty.getProviderId() + ").");
					log.info("Treating remote provider as unauthenticated.");
					return null;
				}

				// Make sure that the suppplied credential is valid for the
				// selected relying party
				X509Certificate[] chain = (X509Certificate[]) req.getAttribute("javax.servlet.request.X509Certificate");
				if (support.getTrust().validate((chain != null && chain.length > 0) ? chain[0] : null, chain, ar_role) ||
                    support.getTrust().validate((chain != null && chain.length > 0) ? chain[0] : null, chain, sp_role)) {
					log.info("Supplied credential validated for this provider.");
					log.info("Request from service provider: (" + relyingParty.getProviderId() + ").");
					return relyingParty.getProviderId();

				} else {
					log.error("Supplied credential ("
							+ credential.getSubjectX500Principal().getName(X500Principal.RFC2253)
							+ ") is NOT valid for provider (" + relyingParty.getProviderId() + ").");
					throw new InvalidProviderCredentialException("Invalid credential.");
				}
			}
		}
	}

	/*
	 * @see edu.internet2.middleware.shibboleth.idp.ProtocolHandler#processRequest(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse, org.opensaml.SAMLRequest,
	 *      edu.internet2.middleware.shibboleth.idp.ProtocolSupport)
	 */
	public SAMLResponse processRequest(HttpServletRequest request, HttpServletResponse response,
			SAMLRequest samlRequest, IdPProtocolSupport support) throws SAMLException, IOException, ServletException {

		if (samlRequest.getQuery() == null || !(samlRequest.getQuery() instanceof SAMLAttributeQuery)) {
			log.error("Protocol Handler can only respond to SAML Attribute Queries.");
			throw new SAMLException(SAMLException.RESPONDER, "General error processing request.");
		}

		RelyingParty relyingParty = null;

		SAMLAttributeQuery attributeQuery = (SAMLAttributeQuery) samlRequest.getQuery();

		if (!fromLegacyProvider(request)) {
			log.info("Remote provider has identified itself as: (" + attributeQuery.getResource() + ").");
		}

		// This is the requester name that will be passed to subsystems
		String effectiveName = null;

		X509Certificate credential = getCredentialFromProvider(request);
		if (credential == null || credential.getSubjectX500Principal().getName(X500Principal.RFC2253).equals("")) {
			log.info("Request is from an unauthenticated service provider.");
		} else {

			// Identify a Relying Party
			relyingParty = support.getServiceProviderMapper().getRelyingParty(attributeQuery.getResource());

			try {
				effectiveName = getEffectiveName(request, relyingParty, support);
			} catch (InvalidProviderCredentialException ipc) {
				throw new SAMLException(SAMLException.REQUESTER, "Invalid credentials for request.");
			}
		}

		if (effectiveName == null) {
			log.debug("Using default Relying Party for unauthenticated provider.");
			relyingParty = support.getServiceProviderMapper().getRelyingParty(null);
		}

		// Fail if we can't honor SAML Subject Confirmation
		if (!fromLegacyProvider(request)) {
			Iterator iterator = attributeQuery.getSubject().getConfirmationMethods();
			boolean hasConfirmationMethod = false;
			while (iterator.hasNext()) {
				log.info("Request contains SAML Subject Confirmation method: (" + (String) iterator.next() + ").");
			}
			if (hasConfirmationMethod) { throw new SAMLException(SAMLException.REQUESTER,
					"This SAML authority cannot honor requests containing the supplied SAML Subject Confirmation Method."); }
		}

		// Map Subject to local principal
		Principal principal = null;
		try {
			SAMLNameIdentifier nameId = attributeQuery.getSubject().getNameIdentifier();
			log.debug("Name Identifier format: (" + nameId.getFormat() + ").");
			NameIdentifierMapping mapping = null;
			try {
				mapping = support.getNameMapper().getNameIdentifierMapping(new URI(nameId.getFormat()));
			} catch (URISyntaxException e) {
				log.error("Invalid Name Identifier format.");
			}
			if (mapping == null) { throw new NameIdentifierMappingException("Name Identifier format not registered."); }

			// Don't honor the request if the active relying party configuration does not contain a mapping with the
			// name identifier format from the request
			if (!Arrays.asList(relyingParty.getNameMapperIds()).contains(mapping.getId())) { throw new NameIdentifierMappingException(
					"Name Identifier format not valid for this relying party."); }

			principal = mapping.getPrincipal(nameId, relyingParty, relyingParty.getIdentityProvider());
			log.info("Request is for principal (" + principal.getName() + ").");

			URL resource = null;
			if (fromLegacyProvider(request)) {
				try {
					resource = new URL(attributeQuery.getResource());
				} catch (MalformedURLException mue) {
					log.error("Request from legacy provider contained an improperly formatted resource "
							+ "identifier.  Attempting to handle request without one.");
				}
			}

			// Get attributes from resolver
			SAMLAttribute[] attrs;
			Iterator requestedAttrsIterator = attributeQuery.getDesignators();
			if (requestedAttrsIterator.hasNext()) {
				log.info("Request designates specific attributes, resolving this set.");
				ArrayList requestedAttrs = new ArrayList();
				while (requestedAttrsIterator.hasNext()) {
					SAMLAttributeDesignator attribute = (SAMLAttributeDesignator) requestedAttrsIterator.next();
					try {
						log.debug("Designated attribute: (" + attribute.getName() + ")");
						requestedAttrs.add(new URI(attribute.getName()));
					} catch (URISyntaxException use) {
						log.error("Request designated an attribute name that does not conform "
								+ "to the required URI syntax (" + attribute.getName() + ").  Ignoring this attribute");
					}
				}

				attrs = support.getReleaseAttributes(principal, relyingParty, effectiveName, resource,
						(URI[]) requestedAttrs.toArray(new URI[0]));
			} else {
				log.info("Request does not designate specific attributes, resolving all available.");
				attrs = support.getReleaseAttributes(principal, relyingParty, effectiveName, resource);
			}

			log.info("Found " + attrs.length + " attribute(s) for " + principal.getName());

			// Put attributes names in the transaction log when it is set to DEBUG
			if (support.getTransactionLog().isDebugEnabled() && attrs.length > 0) {
				StringBuffer attrNameBuffer = new StringBuffer();
				for (int i = 0; i < attrs.length; i++) {
					attrNameBuffer.append("(" + attrs[i].getName() + ")");
				}
				support.getTransactionLog()
						.debug(
								"Attribute assertion generated for provider (" + effectiveName
										+ ") on behalf of principal (" + principal.getName()
										+ ") with the following attributes: " + attrNameBuffer.toString());
			}

			SAMLResponse samlResponse = null;

			if (attrs == null || attrs.length == 0) {
				// No attribute found
				samlResponse = new SAMLResponse(samlRequest.getId(), null, null, null);

			} else {
				// Reference requested subject
				SAMLSubject rSubject = (SAMLSubject) attributeQuery.getSubject().clone();

				ArrayList audiences = new ArrayList();
				if (relyingParty.getProviderId() != null) {
					audiences.add(relyingParty.getProviderId());
				}
				if (relyingParty.getName() != null && !relyingParty.getName().equals(relyingParty.getProviderId())) {
					audiences.add(relyingParty.getName());
				}
				SAMLCondition condition = new SAMLAudienceRestrictionCondition(audiences);

				// Put all attributes into an assertion
				SAMLStatement statement = new SAMLAttributeStatement(rSubject, Arrays.asList(attrs));

				// Set assertion expiration to longest attribute expiration
				long max = 0;
				for (int i = 0; i < attrs.length; i++) {
					if (max < attrs[i].getLifetime()) {
						max = attrs[i].getLifetime();
					}
				}
				Date now = new Date();
				Date then = new Date(now.getTime() + (max * 1000)); // max is in
				// seconds

				SAMLAssertion sAssertion = new SAMLAssertion(relyingParty.getIdentityProvider().getProviderId(), now,
						then, Collections.singleton(condition), null, Collections.singleton(statement));

				// Sign the assertions, if necessary
				boolean metaDataIndicatesSignAssertions = false;
				EntityDescriptor descriptor = support.lookup(relyingParty.getProviderId());
				if (descriptor != null) {
                    AttributeRequesterDescriptor ar = descriptor.getAttributeRequesterDescriptor(org.opensaml.XML.SAML11_PROTOCOL_ENUM);
                    if (ar != null) {
                        if (ar.getWantAssertionsSigned()) {
                            metaDataIndicatesSignAssertions = true;
                        }
                    }
                    if (!metaDataIndicatesSignAssertions) {
    					SPSSODescriptor sp = descriptor.getSPSSODescriptor(org.opensaml.XML.SAML11_PROTOCOL_ENUM);
                        if (sp != null) {
    						if (sp.getWantAssertionsSigned()) {
    							metaDataIndicatesSignAssertions = true;
    						}
    					}
                    }
				}
				if (relyingParty.wantsAssertionsSigned() || metaDataIndicatesSignAssertions) {
					support.signAssertions(new SAMLAssertion[]{sAssertion}, relyingParty);
				}

				samlResponse = new SAMLResponse(samlRequest.getId(), null, Collections.singleton(sAssertion), null);
			}

			if (log.isDebugEnabled()) { // This takes some processing, so only do it if we need to
				log.debug("Dumping generated SAML Response:" + System.getProperty("line.separator")
						+ samlResponse.toString());
			}

			log.info("Successfully created response for principal (" + principal.getName() + ").");

			if (effectiveName == null) {
				if (fromLegacyProvider(request)) {
					support.getTransactionLog().info(
							"Attribute assertion issued to anonymous legacy provider at (" + request.getRemoteAddr()
									+ ") on behalf of principal (" + principal.getName() + ").");
				} else {
					support.getTransactionLog().info(
							"Attribute assertion issued to anonymous provider at (" + request.getRemoteAddr()
									+ ") on behalf of principal (" + principal.getName() + ").");
				}
			} else {
				if (fromLegacyProvider(request)) {
					support.getTransactionLog().info(
							"Attribute assertion issued to legacy provider (" + effectiveName
									+ ") on behalf of principal (" + principal.getName() + ").");
				} else {
					support.getTransactionLog().info(
							"Attribute assertion issued to provider (" + effectiveName + ") on behalf of principal ("
									+ principal.getName() + ").");
				}
			}

			return samlResponse;

		} catch (SAMLException e) {
			if (relyingParty.passThruErrors()) {
				throw new SAMLException(SAMLException.RESPONDER, "General error processing request.", e);
			} else {
				throw new SAMLException(SAMLException.RESPONDER, "General error processing request.");
			}

		} catch (InvalidNameIdentifierException e) {
			log.error("Could not associate the request's subject with a principal: " + e);
			if (relyingParty.passThruErrors()) {
				throw new SAMLException(Arrays.asList(e.getSAMLErrorCodes()), "The supplied Subject was unrecognized.",
						e);
			} else {
				throw new SAMLException(Arrays.asList(e.getSAMLErrorCodes()), "The supplied Subject was unrecognized.");
			}

		} catch (NameIdentifierMappingException e) {
			log.error("Encountered an error while mapping the name identifier from the request: " + e);
			if (relyingParty.passThruErrors()) {
				throw new SAMLException(SAMLException.RESPONDER, "General error processing request.", e);
			} else {
				throw new SAMLException(SAMLException.RESPONDER, "General error processing request.");
			}

		} catch (AAException e) {
			log.error("Encountered an error while resolving resolving attributes: " + e);
			if (relyingParty.passThruErrors()) {
				throw new SAMLException(SAMLException.RESPONDER, "General error processing request.", e);
			} else {
				throw new SAMLException(SAMLException.RESPONDER, "General error processing request.");
			}

		} catch (CloneNotSupportedException e) {
			log.error("Encountered an error while cloning request subject for use in response: " + e);
			if (relyingParty.passThruErrors()) {
				throw new SAMLException(SAMLException.RESPONDER, "General error processing request.", e);
			} else {
				throw new SAMLException(SAMLException.RESPONDER, "General error processing request.");
			}
		}
	}

	private static boolean fromLegacyProvider(HttpServletRequest request) {

		String version = request.getHeader("Shibboleth");
		if (version != null) {
			log.debug("Request from Shibboleth version: " + version);
			return false;
		}
		log.debug("No version header found.");
		return true;
	}

}