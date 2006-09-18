/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.] Licensed under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in
 * writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.idp;

import java.net.URI;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.InvalidCryptoException;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLException;
import org.opensaml.SAMLResponse;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.provider.ChainingMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataFilter;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.security.TrustEngine;
import org.opensaml.security.X509EntityCredential;
import org.opensaml.xml.XMLObject;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.AAAttribute;
import edu.internet2.middleware.shibboleth.aa.AAException;
import edu.internet2.middleware.shibboleth.aa.arp.ArpEngine;
import edu.internet2.middleware.shibboleth.aa.arp.ArpProcessingException;
import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver;
import edu.internet2.middleware.shibboleth.artifact.ArtifactMapper;
import edu.internet2.middleware.shibboleth.common.Credential;
import edu.internet2.middleware.shibboleth.common.RelyingParty;
import edu.internet2.middleware.shibboleth.common.RelyingPartyMapper;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.common.provider.ShibbolethTrustEngine;
import edu.internet2.middleware.shibboleth.metadata.MetadataProviderFactory;

/**
 * Delivers core IdP functionality (Attribute resolution, ARP filtering, Metadata lookup, Signing, Mapping between local &
 * SAML identifiers, etc.) to components that process protocol-specific requests.
 * 
 * @author Walter Hoehn
 */
public class IdPProtocolSupport implements MetadataProvider {

	private static Logger log = Logger.getLogger(IdPProtocolSupport.class.getName());
	private Logger transactionLog;
	private IdPConfig config;
	private RelyingPartyMapper spMapper;
	private ArpEngine arpEngine;
	private AttributeResolver resolver;
	private ArtifactMapper artifactMapper;
	private Semaphore throttle;
	private TrustEngine<X509EntityCredential> trust = new ShibbolethTrustEngine();
	private ChainingMetadataProvider wrappedMetadataProvider = new ChainingMetadataProvider();

	IdPProtocolSupport(IdPConfig config, Logger transactionLog, RelyingPartyMapper spMapper, ArpEngine arpEngine,
			AttributeResolver resolver, ArtifactMapper artifactMapper) throws ShibbolethConfigurationException {

		this.transactionLog = transactionLog;
		this.config = config;
		this.spMapper = spMapper;
		spMapper.setMetadata(this);
		this.arpEngine = arpEngine;
		this.resolver = resolver;
		this.artifactMapper = artifactMapper;

		// Load a semaphore that throttles how many requests the IdP will handle at once
		throttle = new Semaphore(config.getMaxThreads());
	}

	public Logger getTransactionLog() {

		return transactionLog;
	}

	public IdPConfig getIdPConfig() {

		return config;
	}

	public RelyingPartyMapper getRelyingPartyMapper() {

		return spMapper;
	}

	public void signAssertions(SAMLAssertion[] assertions, RelyingParty relyingParty) throws InvalidCryptoException,
			SAMLException {

		if (relyingParty.getIdentityProvider().getSigningCredential() == null
				|| relyingParty.getIdentityProvider().getSigningCredential().getPrivateKey() == null) { throw new InvalidCryptoException(
				SAMLException.RESPONDER, "Invalid signing credential."); }

		for (int i = 0; i < assertions.length; i++) {
			String assertionAlgorithm;
			if (relyingParty.getIdentityProvider().getSigningCredential().getCredentialType() == Credential.RSA) {
				assertionAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
			} else if (relyingParty.getIdentityProvider().getSigningCredential().getCredentialType() == Credential.DSA) {
				assertionAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_DSA;
			} else {
				throw new InvalidCryptoException(SAMLException.RESPONDER,
						"The Shibboleth IdP currently only supports signing with RSA and DSA keys.");
			}

			try {
				throttle.enter();
				assertions[i].sign(assertionAlgorithm, relyingParty.getIdentityProvider().getSigningCredential()
						.getPrivateKey(), Arrays.asList(relyingParty.getIdentityProvider().getSigningCredential()
						.getX509CertificateChain()));
			} finally {
				throttle.exit();
			}
		}
	}

	public void signResponse(SAMLResponse response, RelyingParty relyingParty) throws SAMLException {

		// Make sure we have an appropriate credential
		if (relyingParty.getIdentityProvider().getSigningCredential() == null
				|| relyingParty.getIdentityProvider().getSigningCredential().getPrivateKey() == null) { throw new InvalidCryptoException(
				SAMLException.RESPONDER, "Invalid signing credential."); }

		// Sign the response
		String responseAlgorithm;
		if (relyingParty.getIdentityProvider().getSigningCredential().getCredentialType() == Credential.RSA) {
			responseAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
		} else if (relyingParty.getIdentityProvider().getSigningCredential().getCredentialType() == Credential.DSA) {
			responseAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_DSA;
		} else {
			throw new InvalidCryptoException(SAMLException.RESPONDER,
					"The Shibboleth IdP currently only supports signing with RSA and DSA keys.");
		}
		try {
			throttle.enter();
			response.sign(responseAlgorithm, relyingParty.getIdentityProvider().getSigningCredential().getPrivateKey(),
					Arrays.asList(relyingParty.getIdentityProvider().getSigningCredential().getX509CertificateChain()));
		} finally {
			throttle.exit();
		}
	}

	protected void addMetadataProvider(Element element) {

		log.debug("Found Metadata Provider configuration element.");
		if (!element.getTagName().equals("MetadataProvider")) {
			log.error("Error while attemtping to load Metadata Provider.  Malformed provider specificaion.");
			return;
		}

		try {
			wrappedMetadataProvider.addMetadataProvider(MetadataProviderFactory.loadProvider(element));
		} catch (MetadataProviderException e) {
			log.error("Unable to load Metadata Provider.  Skipping...");
		}

	}

	public Collection<? extends SAMLAttribute> getReleaseAttributes(Principal principal, RelyingParty relyingParty,
			String requester) throws AAException {

		try {
			Collection<URI> potentialAttributes = arpEngine.listPossibleReleaseAttributes(principal, requester);
			return getReleaseAttributes(principal, relyingParty, requester, potentialAttributes);

		} catch (ArpProcessingException e) {
			log.error("An error occurred while processing the ARPs for principal (" + principal.getName() + ") :"
					+ e.getMessage());
			throw new AAException("Error retrieving data for principal.");
		}
	}

	public Collection<? extends SAMLAttribute> getReleaseAttributes(Principal principal, RelyingParty relyingParty,
			String requester, Collection<URI> attributeNames) throws AAException {

		try {
			Map<String, AAAttribute> attributes = new HashMap<String, AAAttribute>();
			for (URI name : attributeNames) {

				AAAttribute attribute = new AAAttribute(name.toString(), false);
				attributes.put(attribute.getName(), attribute);
			}

			Collection<URI> constraintAttributes = arpEngine.listRequiredConstraintAttributes(principal, requester,
					attributeNames);
			for (URI name : constraintAttributes) {
				if (!attributes.containsKey(name.toString())) {
					// don't care about schema hack since these attributes won't be returned to SP
					AAAttribute attribute = new AAAttribute(name.toString(), false);
					attributes.put(attribute.getName(), attribute);
				}
			}

			return resolveAttributes(principal, requester, relyingParty.getIdentityProvider().getProviderId(),
					attributes);

		} catch (SAMLException e) {
			log.error("An error occurred while creating attributes for principal (" + principal.getName() + ") :"
					+ e.getMessage());
			throw new AAException("Error retrieving data for principal.");

		} catch (ArpProcessingException e) {
			log.error("An error occurred while processing the ARPs for principal (" + principal.getName() + ") :"
					+ e.getMessage());
			throw new AAException("Error retrieving data for principal.");
		}
	}

	public Collection<? extends SAMLAttribute> resolveAttributes(Principal principal, String requester,
			String responder, Map<String, AAAttribute> attributeSet) throws ArpProcessingException {

		resolver.resolveAttributes(principal, requester, responder, attributeSet);
		arpEngine.filterAttributes(attributeSet.values(), principal, requester);
		return attributeSet.values();
	}

	public Collection<? extends SAMLAttribute> resolveAttributesNoPolicies(Principal principal, String requester,
			String responder, Map<String, AAAttribute> attributeSet) {

		resolver.resolveAttributes(principal, requester, responder, attributeSet);
		return attributeSet.values();
	}

	/**
	 * Cleanup resources that won't be released when this object is garbage-collected
	 */
	public void destroy() {

		resolver.destroy();
		arpEngine.destroy();
	}

	public ArtifactMapper getArtifactMapper() {

		return artifactMapper;
	}

	public TrustEngine<X509EntityCredential> getTrust() {

		return trust;
	}

	public boolean requireValidMetadata() {

		return wrappedMetadataProvider.requireValidMetadata();
	}

	public void setRequireValidMetadata(boolean requireValidMetadata) {

		wrappedMetadataProvider.setRequireValidMetadata(requireValidMetadata);
	}

	public MetadataFilter getMetadataFilter() {

		return wrappedMetadataProvider.getMetadataFilter();
	}

	public void setMetadataFilter(MetadataFilter newFilter) throws MetadataProviderException {

		wrappedMetadataProvider.setMetadataFilter(newFilter);
	}

	public XMLObject getMetadata() throws MetadataProviderException {

		return wrappedMetadataProvider.getMetadata();
	}

	public EntitiesDescriptor getEntitiesDescriptor(String name) throws MetadataProviderException {

		return wrappedMetadataProvider.getEntitiesDescriptor(name);
	}

	public EntityDescriptor getEntityDescriptor(String entityID) throws MetadataProviderException {

		return wrappedMetadataProvider.getEntityDescriptor(entityID);
	}

	public List<RoleDescriptor> getRole(String entityID, QName roleName) throws MetadataProviderException {

		return wrappedMetadataProvider.getRole(entityID, roleName);
	}

	public RoleDescriptor getRole(String entityID, QName roleName, String supportedProtocol)
			throws MetadataProviderException {

		return wrappedMetadataProvider.getRole(entityID, roleName, supportedProtocol);
	}

	public int providerCount() {

		return wrappedMetadataProvider.getProviders().size();
	}

	private class Semaphore {

		private int value;

		public Semaphore(int value) {

			this.value = value;
		}

		public synchronized void enter() {

			--value;
			if (value < 0) {
				try {
					wait();
				} catch (InterruptedException e) {
					// squelch and continue
				}
			}
		}

		public synchronized void exit() {

			++value;
			notify();
		}
	}

}