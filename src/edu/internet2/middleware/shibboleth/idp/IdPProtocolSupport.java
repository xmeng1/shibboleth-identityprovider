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
import java.net.URL;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.InvalidCryptoException;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLException;
import org.opensaml.SAMLResponse;
import org.opensaml.artifact.Artifact;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.AAAttribute;
import edu.internet2.middleware.shibboleth.aa.AAAttributeSet;
import edu.internet2.middleware.shibboleth.aa.AAException;
import edu.internet2.middleware.shibboleth.aa.arp.ArpEngine;
import edu.internet2.middleware.shibboleth.aa.arp.ArpProcessingException;
import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver;
import edu.internet2.middleware.shibboleth.artifact.ArtifactMapper;
import edu.internet2.middleware.shibboleth.common.Credential;
import edu.internet2.middleware.shibboleth.common.NameMapper;
import edu.internet2.middleware.shibboleth.common.RelyingParty;
import edu.internet2.middleware.shibboleth.common.ServiceProviderMapper;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.common.Trust;
import edu.internet2.middleware.shibboleth.common.provider.ShibbolethTrust;
import edu.internet2.middleware.shibboleth.metadata.EntitiesDescriptor;
import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;
import edu.internet2.middleware.shibboleth.metadata.Metadata;
import edu.internet2.middleware.shibboleth.metadata.MetadataException;

/**
 * Delivers core IdP functionality (Attribute resolution, ARP filtering, Metadata lookup, Signing, Mapping between local &
 * SAML identifiers, etc.) to components that process protocol-specific requests.
 * 
 * @author Walter Hoehn
 */
public class IdPProtocolSupport implements Metadata {

	private static Logger log = Logger.getLogger(IdPProtocolSupport.class.getName());
	private Logger transactionLog;
	private IdPConfig config;
	private ArrayList metadata = new ArrayList();
	private NameMapper nameMapper;
	private ServiceProviderMapper spMapper;
	private ArpEngine arpEngine;
	private AttributeResolver resolver;
	private ArtifactMapper artifactMapper;
	private Semaphore throttle;
	private Trust trust = new ShibbolethTrust();

	IdPProtocolSupport(IdPConfig config, Logger transactionLog, NameMapper nameMapper, ServiceProviderMapper spMapper,
			ArpEngine arpEngine, AttributeResolver resolver, ArtifactMapper artifactMapper)
			throws ShibbolethConfigurationException {

		this.transactionLog = transactionLog;
		this.config = config;
		this.nameMapper = nameMapper;
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

	public NameMapper getNameMapper() {

		return nameMapper;
	}

	public ServiceProviderMapper getServiceProviderMapper() {

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
			metadata.add(MetadataProviderFactory.loadProvider(element));
		} catch (MetadataException e) {
			log.error("Unable to load Metadata Provider.  Skipping...");
		}
	}

	public int providerCount() {

		return metadata.size();
	}

	public EntityDescriptor lookup(String providerId, boolean strict) {

		Iterator iterator = metadata.iterator();
		while (iterator.hasNext()) {
			EntityDescriptor provider = ((Metadata) iterator.next()).lookup(providerId);
			if (provider != null) { return provider; }
		}
		return null;
	}

	public EntityDescriptor lookup(Artifact artifact, boolean strict) {

		Iterator iterator = metadata.iterator();
		while (iterator.hasNext()) {
			EntityDescriptor provider = ((Metadata) iterator.next()).lookup(artifact);
			if (provider != null) { return provider; }
		}
		return null;
	}

	public EntityDescriptor lookup(String id) {

		return lookup(id, true);
	}

	public EntityDescriptor lookup(Artifact artifact) {

		return lookup(artifact, true);
	}

	public EntityDescriptor getRootEntity() {

		return null;
	}

	public EntitiesDescriptor getRootEntities() {

		return null;
	}

	public SAMLAttribute[] getReleaseAttributes(Principal principal, RelyingParty relyingParty, String requester,
			URL resource) throws AAException {

		try {
			URI[] potentialAttributes = arpEngine.listPossibleReleaseAttributes(principal, requester, resource);
			return getReleaseAttributes(principal, relyingParty, requester, resource, potentialAttributes);

		} catch (ArpProcessingException e) {
			log.error("An error occurred while processing the ARPs for principal (" + principal.getName() + ") :"
					+ e.getMessage());
			throw new AAException("Error retrieving data for principal.");
		}
	}

	public SAMLAttribute[] getReleaseAttributes(Principal principal, RelyingParty relyingParty, String requester,
			URL resource, URI[] attributeNames) throws AAException {

		try {
			AAAttributeSet attributeSet = new AAAttributeSet();
			for (int i = 0; i < attributeNames.length; i++) {

				AAAttribute attribute = null;
				if (relyingParty.wantsSchemaHack()) {
					attribute = new AAAttribute(attributeNames[i].toString(), true);
				} else {
					attribute = new AAAttribute(attributeNames[i].toString(), false);
				}

				attributeSet.add(attribute);
			}

			return resolveAttributes(principal, requester, relyingParty.getIdentityProvider().getProviderId(),
					resource, attributeSet);

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

	public SAMLAttribute[] resolveAttributes(Principal principal, String requester, String responder, URL resource,
			AAAttributeSet attributeSet) throws ArpProcessingException {

		resolver.resolveAttributes(principal, requester, responder, attributeSet);
		arpEngine.filterAttributes(attributeSet, principal, requester, resource);
		return attributeSet.getAttributes();
	}

	public SAMLAttribute[] resolveAttributesNoPolicies(Principal principal, String requester, String responder,
			URL resource, AAAttributeSet attributeSet) throws ArpProcessingException {

		resolver.resolveAttributes(principal, requester, responder, attributeSet);
		arpEngine.filterAttributes(attributeSet, principal, requester, resource);
		return attributeSet.getAttributes();
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

	public Trust getTrust() {

		return trust;
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