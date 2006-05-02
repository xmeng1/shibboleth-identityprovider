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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
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
import org.opensaml.XML;
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

	private String authenticateAs(String assertedId, X509Certificate[] chain, IdPProtocolSupport support)
			throws InvalidProviderCredentialException {

		// See if we have metadata for this provider
		EntityDescriptor provider = support.lookup(assertedId);
		if (provider == null) {
			log.info("No metadata found for providerId: (" + assertedId + ").");
			return null;
		} else {
			log.info("Metadata found for providerId: (" + assertedId + ").");
		}
		RoleDescriptor ar_role = provider.getAttributeRequesterDescriptor(XML.SAML11_PROTOCOL_ENUM);
		RoleDescriptor sp_role = provider.getSPSSODescriptor(XML.SAML11_PROTOCOL_ENUM);
		if (ar_role == null && sp_role == null) {
			log.info("SPSSO and Stand-Alone Requester roles not found in metadata for provider: (" + assertedId + ").");
			return null;
		}

		// Make sure that the supplied credential is valid for the selected provider role.
		if ((ar_role != null && support.getTrust().validate(chain[0], chain, ar_role))
				|| (sp_role != null && support.getTrust().validate(chain[0], chain, sp_role))) {
			log.info("Supplied credentials validated for this provider.");
			return assertedId;
		} else {
			log.error("Supplied credentials (" + chain[0].getSubjectX500Principal().getName(X500Principal.RFC2253)
					+ ") are NOT valid for provider (" + assertedId + ").");
			throw new InvalidProviderCredentialException("Invalid credentials.");
		}
	}

	/*
	 * @see edu.internet2.middleware.shibboleth.idp.ProtocolHandler#processRequest(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse, org.opensaml.SAMLRequest,
	 *      edu.internet2.middleware.shibboleth.idp.ProtocolSupport)
	 */
	public SAMLResponse processRequest(HttpServletRequest request, HttpServletResponse response,
			SAMLRequest samlRequest, IdPProtocolSupport support) throws SAMLException, IOException, ServletException {

		if (samlRequest == null || samlRequest.getQuery() == null
				|| !(samlRequest.getQuery() instanceof SAMLAttributeQuery)) {
			log.error("Protocol Handler can only respond to SAML Attribute Queries.");
			throw new SAMLException("General error processing request.");
		}

		RelyingParty relyingParty = null;
		SAMLAttributeQuery attributeQuery = (SAMLAttributeQuery) samlRequest.getQuery();

		// This is the requester name that will be passed to subsystems
		String effectiveName = null;

		// Log the physical credential supplied, if any.
		X509Certificate[] credentials = (X509Certificate[]) request
				.getAttribute("javax.servlet.request.X509Certificate");
		if (credentials == null || credentials.length == 0
				|| credentials[0].getSubjectX500Principal().getName(X500Principal.RFC2253).equals("")) {
			log.info("Request contained no credentials, treating as an unauthenticated service provider.");
		} else {
			log.info("Request contains credentials: ("
					+ credentials[0].getSubjectX500Principal().getName(X500Principal.RFC2253) + ").");

			// Try and authenticate the requester as any of the potentially relevant identifiers we know.
			try {
				if (attributeQuery.getResource() != null) {
					log.info("Remote provider has identified itself as: (" + attributeQuery.getResource() + ").");
					effectiveName = authenticateAs(attributeQuery.getResource(), credentials, support);
				}

				if (effectiveName == null) {
					log
							.info("Remote provider not yet identified, attempting to derive requesting provider from credentials.");

					// Try the additional candidates.
					String[] candidateNames = getCredentialNames(credentials[0]);
					for (int c = 0; effectiveName == null && c < candidateNames.length; c++) {
						effectiveName = authenticateAs(candidateNames[c], credentials, support);
					}
				}
			} catch (InvalidProviderCredentialException ipc) {
				throw new SAMLException(SAMLException.REQUESTER, "Invalid credentials for request.");
			}
		}

		if (effectiveName == null) {
			log.info("Unable to locate metadata about provider, treating as an unauthenticated service provider.");
			relyingParty = support.getServiceProviderMapper().getRelyingParty(null);
			if (log.isDebugEnabled()) {
				log.debug("Using default Relying Party, " + relyingParty.getName() + " for unauthenticated provider.");
			}
		} else {
			// Identify a Relying Party
			log.debug("Mapping authenticated provider (" + effectiveName + ") to Relying Party.");
			relyingParty = support.getServiceProviderMapper().getRelyingParty(effectiveName);
		}

		// Fail if we can't honor SAML Subject Confirmation unless the only one supplied is
		// bearer, in which case this is probably a Shib 1.1 query, and we'll let it slide for now.
		// TODO: remove the compatibility with 1.1 and be strict about this?
		boolean hasConfirmationMethod = false;
		boolean hasOnlyBearer = true;
		Iterator iterator = attributeQuery.getSubject().getConfirmationMethods();
		while (iterator.hasNext()) {
			String method = (String) iterator.next();
			log.info("Request contains SAML Subject Confirmation method: (" + method + ").");
			hasConfirmationMethod = true;
			if (!method.equals(SAMLSubject.CONF_BEARER)) hasOnlyBearer = false;
		}
		if (hasConfirmationMethod && !hasOnlyBearer) { throw new SAMLException(SAMLException.REQUESTER,
				"This SAML authority cannot honor requests containing the supplied SAML Subject Confirmation Method(s)."); }

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

			// Get attributes from resolver
			Collection<? extends SAMLAttribute> attrs;
			Iterator requestedAttrsIterator = attributeQuery.getDesignators();
			if (requestedAttrsIterator.hasNext()) {
				log.info("Request designates specific attributes, resolving this set.");
				ArrayList<URI> requestedAttrs = new ArrayList<URI>();
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

				attrs = support.getReleaseAttributes(principal, relyingParty, effectiveName, requestedAttrs);
			} else {
				log.info("Request does not designate specific attributes, resolving all available.");
				attrs = support.getReleaseAttributes(principal, relyingParty, effectiveName, null);
			}

			log.info("Found " + attrs.size() + " attribute(s) for " + principal.getName());

			// Put attributes names in the transaction log when it is set to DEBUG
			if (support.getTransactionLog().isDebugEnabled() && attrs.size() > 0) {
				StringBuffer attrNameBuffer = new StringBuffer();
				for (SAMLAttribute attr : attrs) {
					attrNameBuffer.append("(" + attr.getName() + ")");
				}
				support.getTransactionLog()
						.debug(
								"Attribute assertion generated for provider (" + effectiveName
										+ ") on behalf of principal (" + principal.getName()
										+ ") with the following attributes: " + attrNameBuffer.toString());
			}

			SAMLResponse samlResponse = null;

			if (attrs == null || attrs.size() == 0) {
				// No attribute found
				samlResponse = new SAMLResponse(samlRequest.getId(), null, null, null);

			} else {
				// Reference requested subject
				SAMLSubject rSubject = (SAMLSubject) attributeQuery.getSubject().clone();

				ArrayList<String> audiences = new ArrayList<String>();
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
				for (SAMLAttribute attr : attrs) {
					if (max < attr.getLifetime()) {
						max = attr.getLifetime();
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
					AttributeRequesterDescriptor ar = descriptor
							.getAttributeRequesterDescriptor(org.opensaml.XML.SAML11_PROTOCOL_ENUM);
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
				support.getTransactionLog().info(
						"Attribute assertion issued to anonymous provider at (" + request.getRemoteAddr()
								+ ") on behalf of principal (" + principal.getName() + ").");
			} else {
				support.getTransactionLog().info(
						"Attribute assertion issued to provider (" + effectiveName + ") on behalf of principal ("
								+ principal.getName() + ").");
			}

			return samlResponse;

		} catch (SAMLException e) {
			if (relyingParty.passThruErrors()) {
				throw new SAMLException("General error processing request.", e);
			} else {
				throw new SAMLException("General error processing request.");
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
				throw new SAMLException("General error processing request.", e);
			} else {
				throw new SAMLException("General error processing request.");
			}

		} catch (AAException e) {
			log.error("Encountered an error while resolving resolving attributes: " + e);
			if (relyingParty.passThruErrors()) {
				throw new SAMLException("General error processing request.", e);
			} else {
				throw new SAMLException("General error processing request.");
			}

		} catch (CloneNotSupportedException e) {
			log.error("Encountered an error while cloning request subject for use in response: " + e);
			if (relyingParty.passThruErrors()) {
				throw new SAMLException("General error processing request.", e);
			} else {
				throw new SAMLException("General error processing request.");
			}
		}
	}
}