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

package edu.internet2.middleware.shibboleth.common;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObject;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.NodeList;

import edu.internet2.middleware.shibboleth.idp.IdPConfig;

/**
 * Class for determining the effective relying party from the unique id of the service provider. Checks first for an
 * exact match on the service provider, then for membership in a group of providers (perhaps a federation). Uses the
 * default relying party if neither is found.
 * 
 * @author Walter Hoehn
 */
public class RelyingPartyMapper {

	private static Logger log = Logger.getLogger(RelyingPartyMapper.class.getName());
	protected Map<String, NamedRelyingParty> relyingParties = new HashMap<String, NamedRelyingParty>();
	protected RelyingParty defaultRelyingParty;
	protected RelyingParty anonymousRelyingParty;

	private MetadataProvider metaData;
	private Credentials credentials;

	public RelyingPartyMapper(Element rawConfig, Credentials credentials) throws RelyingPartyMapperException {

		if (credentials == null) { throw new IllegalArgumentException(
				"RelyingPartyMapper cannot be started without proper access to the IdP configuration."); }

		this.credentials = credentials;

		// Load specified <RelyingParty/> elements
		NodeList itemElements = rawConfig.getElementsByTagNameNS(IdPConfig.configNameSpace, "RelyingParty");
		for (int i = 0; i < itemElements.getLength(); i++) {
			addRelyingParty((Element) itemElements.item(i));
		}

		// Load <AnonymousRelyingParty/> element, if specified
		itemElements = rawConfig.getElementsByTagNameNS(IdPConfig.configNameSpace, "AnonymousRelyingParty");
		if (itemElements.getLength() > 1) {
			log.error("Found multiple <AnonymousRelyingParty/> elements.  Ignoring all but the first...");
		}
		if (itemElements.getLength() < 1) {
			log.error("No <AnonymousRelyingParty/> elements found.  Disabling support for responding "
					+ "to anonymous relying parties.");
		} else {
			addAnonymousRelyingParty((Element) itemElements.item(0));
		}

		// Load <DefaultRelyingParty/> element, if specified
		itemElements = rawConfig.getElementsByTagNameNS(IdPConfig.configNameSpace, "DefaultRelyingParty");
		if (itemElements.getLength() > 1) {
			log.error("Found multiple <DefaultRelyingParty/> elements.  Ignoring all but the first...");
		}
		if (itemElements.getLength() < 1) {
			log.error("No <DefaultRelyingParty/> elements found.  Disabling support for responding "
					+ "to anonymous relying parties.");
		} else {
			addDefaultRelyingParty((Element) itemElements.item(0));
		}
	}

	public boolean anonymousSuported() {

		return (anonymousRelyingParty != null);
	}

	public RelyingParty getAnonymousRelyingParty() {

		return anonymousRelyingParty;

	}

	public void setMetadata(MetadataProvider metadata) {

		this.metaData = metadata;
	}

	private NamedRelyingParty findRelyingPartyByGroup(String providerIdFromSP) {

		if (metaData == null) { return null; }

		// Attempt to lookup the entity in the metdata
		EntityDescriptor provider = null;
		try {
			provider = metaData.getEntityDescriptor(providerIdFromSP);
		} catch (MetadataProviderException e) {
			log.error("Problem encountered during metadata lookup of entity (" + providerIdFromSP + "): " + e);
		}

		// OK, if we found it travel recurse down the tree of parent entities
		if (provider != null) {
			EntitiesDescriptor parent = getParentEntitiesDescriptor(provider);

			while (parent != null) {
				if (parent.getName() != null) {
					if (relyingParties.containsKey(parent.getName())) {
						log.info("Found matching Relying Party for group (" + parent.getName() + ").");
						return (NamedRelyingParty) relyingParties.get(parent.getName());
					} else {
						log.debug("Provider is a member of group (" + parent.getName()
								+ "), but no matching Relying Party was found.");
					}
				}
				parent = getParentEntitiesDescriptor(parent);
			}
		}
		return null;
	}

	/**
	 * Returns the appropriate relying party for the supplied service provider id.
	 */
	public RelyingParty getRelyingParty(String providerIdFromSP) {

		if (providerIdFromSP == null || providerIdFromSP.equals("")) { throw new IllegalArgumentException(
				"Incorrect use of ServiceProviderMapper.  Cannot lookup relying party without a provider ID."); }

		// Look for a configuration for the specific relying party
		if (relyingParties.containsKey(providerIdFromSP)) {
			log.info("Found Relying Party for (" + providerIdFromSP + ").");
			return (RelyingParty) relyingParties.get(providerIdFromSP);
		}

		// Lookup by group
		// Next, check to see if the relying party is in any groups
		NamedRelyingParty groupParty = findRelyingPartyByGroup(providerIdFromSP);
		if (groupParty != null) {
			log.info("Provider is a member of Relying Party (" + groupParty.getName() + ").");
			return groupParty;
		}

		// Use default if we have one
		if (defaultRelyingParty != null) {
			log.debug("No matching relying party found.  Using default relying party.");
			return defaultRelyingParty;
		}

		// Alright, there's nothing available to us
		return null;

	}

	private void addRelyingParty(Element e) throws RelyingPartyMapperException {

		log.debug("Found a Relying Party configuration element.");
		try {
			if (e.getLocalName().equals("RelyingParty")) {
				NamedRelyingParty party = new NamedRelyingParty(e, credentials);
				log.debug("Relying Party (" + party.getName() + ") loaded.");
				relyingParties.put(party.getName(), party);
			}
		} catch (RelyingPartyMapperException exc) {
			log.error("Encountered an error while attempting to load Relying Party configuration.  Skipping...");
		}
	}

	private void addAnonymousRelyingParty(Element e) throws RelyingPartyMapperException {

		log.debug("Found an Anonymous Relying Party configuration element.");
		try {
			if (e.getLocalName().equals("AnonymousRelyingParty")) {
				RelyingParty party = new RelyingPartyImpl(e, credentials);
				log.debug("Anonymous Relying Party loaded.");
				anonymousRelyingParty = party;
			}
		} catch (RelyingPartyMapperException exc) {
			log.error("Encountered an error while attempting to load Anonymous Relying"
					+ " Party configuration.  Skipping...");
		}
	}

	private void addDefaultRelyingParty(Element e) throws RelyingPartyMapperException {

		log.debug("Found a Default Relying Party configuration element.");
		try {
			if (e.getLocalName().equals("DefaultRelyingParty")) {
				RelyingParty party = new RelyingPartyImpl(e, credentials);
				log.debug("Default Relying Party loaded.");
				defaultRelyingParty = party;
			}
		} catch (RelyingPartyMapperException exc) {
			log.error("Encountered an error while attempting to load Default "
					+ "Relying Party configuration.  Skipping...");
		}
	}

	private EntitiesDescriptor getParentEntitiesDescriptor(XMLObject entity) {

		Object parent = entity.getParent();

		if (parent instanceof EntitiesDescriptor) { return (EntitiesDescriptor) parent; }

		return null;
	}

	/**
	 * Base relying party implementation.
	 * 
	 * @author Walter Hoehn
	 */
	protected class RelyingPartyImpl implements RelyingParty {

		private RelyingPartyIdentityProvider identityProvider;
		private String providerId;
		private boolean passThruErrors = false;
		private boolean forceAttributePush = false;
		private boolean forceAttributeNoPush = false;
		private boolean singleAssertion = false;
		private boolean defaultToPOST = true;
		private boolean wantsAssertionsSigned = false;
		private int preferredArtifactType = 1;
		private String defaultTarget;
		private Map<String, String> extensionAttributes = new HashMap<String, String>();
		private Collection<String> knownAttributes = Arrays.asList(new String[]{"providerId", "passThruErrors",
				"defaultToPOSTProfile", "singleAssertion", "signAssertions", "defaultTarget", "forceAttributePush",
				"preferredArtifactType", "signingCredential"});

		public RelyingPartyImpl(Element partyConfig, Credentials credentials) throws RelyingPartyMapperException {

			// Process overrides for global configuration data
			String attribute = ((Element) partyConfig).getAttribute("providerId");
			if (attribute == null || attribute.equals("")) {
				log.error("Relying Party providerId not set.  Add a (providerId) " + "attribute to <RelyingParty>.");
				throw new RelyingPartyMapperException("Required configuration not specified.");
			}
			providerId = attribute;
			log.debug("Setting providerId for Relying Party to (" + attribute + ").");

			attribute = ((Element) partyConfig).getAttribute("passThruErrors");
			if (attribute != null && !attribute.equals("")) {
				log.debug("Setting passThruErrors for Relying Pary with (" + attribute + ").");
				passThruErrors = Boolean.valueOf(attribute).booleanValue();
			}

			// SSO profile defaulting
			attribute = ((Element) partyConfig).getAttribute("defaultToPOSTProfile");
			if (attribute != null && !attribute.equals("")) {
				defaultToPOST = Boolean.valueOf(attribute).booleanValue();
			}
			if (defaultToPOST) {
				log.debug("Relying party defaults to POST profile.");
			} else {
				log.debug("Relying party defaults to Artifact profile.");
			}

			attribute = ((Element) partyConfig).getAttribute("singleAssertion");
			if (attribute != null && !attribute.equals("")) {
				singleAssertion = Boolean.valueOf(attribute).booleanValue();
			}
			if (singleAssertion) {
				log.debug("Relying party defaults to a single assertion when pushing attributes.");
			} else {
				log.debug("Relying party defaults to multiple assertions when pushing attributes.");
			}

			// Relying Party wants assertions signed?
			attribute = ((Element) partyConfig).getAttribute("signAssertions");
			if (attribute != null && !attribute.equals("")) {
				wantsAssertionsSigned = Boolean.valueOf(attribute).booleanValue();
			}
			if (wantsAssertionsSigned) {
				log.debug("Relying party wants SAML Assertions to be signed.");
			} else {
				log.debug("Relying party does not want SAML Assertions to be signed.");
			}

			// Set a default target for use in artifact redirects
			defaultTarget = ((Element) partyConfig).getAttribute("defaultTarget");

			// Determine whether or not we are forcing attribute push on or off
			String forcePush = ((Element) partyConfig).getAttribute("forceAttributePush");
			String forceNoPush = ((Element) partyConfig).getAttribute("forceAttributeNoPush");

			if (forcePush != null && Boolean.valueOf(forcePush).booleanValue() && forceNoPush != null
					&& Boolean.valueOf(forceNoPush).booleanValue()) {
				log.error("Invalid configuration:  Attribute push is forced to ON and OFF for this relying "
						+ "party.  Turning off forcing in favor of profile defaults.");
			} else {
				forceAttributePush = Boolean.valueOf(forcePush).booleanValue();
				forceAttributeNoPush = Boolean.valueOf(forceNoPush).booleanValue();
				log.debug("Attribute push forcing is set to (" + forceAttributePush + ").");
				log.debug("No attribute push forcing is set to (" + forceAttributeNoPush + ").");
			}

			attribute = ((Element) partyConfig).getAttribute("preferredArtifactType");
			if (attribute != null && !attribute.equals("")) {
				log.debug("Overriding preferredArtifactType for Relying Pary with (" + attribute + ").");
				try {
					preferredArtifactType = Integer.parseInt(attribute);
				} catch (NumberFormatException e) {
					log.error("(preferredArtifactType) attribute to is not a valid integer.");
					throw new RelyingPartyMapperException("Configuration is invalid.");
				}
				log.debug("Preferred artifact type: (" + preferredArtifactType + ").");
			}

			// Load the credential for signing
			String credentialName = ((Element) partyConfig).getAttribute("signingCredential");
			Credential signingCredential = credentials.getCredential(credentialName);
			if (signingCredential == null) {
				if (credentialName == null || credentialName.equals("")) {
					log.error("Relying Party credential not set.  Add a (signingCredential) "
							+ "attribute to <RelyingParty>.");
					throw new RelyingPartyMapperException("Required configuration not specified.");
				} else {
					log.error("Relying Party credential invalid.  Fix the (signingCredential) attribute "
							+ "on <RelyingParty>.");
					throw new RelyingPartyMapperException("Required configuration is invalid.");
				}

			}

			// Initialize and Identity Provider object for this use by this relying party
			identityProvider = new RelyingPartyIdentityProvider(providerId, signingCredential);

			// Track extension attributes
			NamedNodeMap nodeMap = ((Element) partyConfig).getAttributes();
			for (int i = 0; i < nodeMap.getLength(); i++) {
				Attr attr = (Attr) nodeMap.item(i);
				if (!knownAttributes.contains(attr.getName())) {
					extensionAttributes.put(attr.getName(), attr.getValue());
				}
			}
		}

		public IdentityProvider getIdentityProvider() {

			return identityProvider;
		}

		public boolean passThruErrors() {

			return passThruErrors;
		}

		public boolean forceAttributePush() {

			return forceAttributePush;
		}

		public boolean forceAttributeNoPush() {

			return forceAttributeNoPush;
		}

		public boolean singleAssertion() {

			return singleAssertion;
		}

		public boolean defaultToPOSTProfile() {

			return defaultToPOST;
		}

		public boolean wantsAssertionsSigned() {

			return wantsAssertionsSigned;
		}

		public int getPreferredArtifactType() {

			return preferredArtifactType;
		}

		public String getDefaultTarget() {

			return defaultTarget;
		}

		public String getCustomAttribute(String name) {

			return extensionAttributes.get(name);
		}

		/**
		 * Default identity provider implementation.
		 * 
		 * @author Walter Hoehn
		 */
		protected class RelyingPartyIdentityProvider implements IdentityProvider {

			private String providerId;
			private Credential credential;

			public RelyingPartyIdentityProvider(String providerId, Credential credential) {

				this.providerId = providerId;
				this.credential = credential;
			}

			/*
			 * @see edu.internet2.middleware.shibboleth.common.IdentityProvider#getProviderId()
			 */
			public String getProviderId() {

				return providerId;
			}

			/*
			 * @see edu.internet2.middleware.shibboleth.common.IdentityProvider#getSigningCredential()
			 */
			public Credential getSigningCredential() {

				return credential;
			}
		}

	}

	class NamedRelyingParty extends RelyingPartyImpl {

		private String name;

		public NamedRelyingParty(Element partyConfig, Credentials credentials) throws RelyingPartyMapperException {

			super(partyConfig, credentials);
			// Get party name
			name = ((Element) partyConfig).getAttribute("name");
			if (name == null || name.equals("")) {
				log.error("Relying Party name not set.  Add a (name) attribute to <RelyingParty>.");
				throw new RelyingPartyMapperException("Required configuration not specified.");
			}
			log.debug("Loading Relying Party: (" + name + ").");
		}

		public String getName() {

			return name;
		}
	}
}