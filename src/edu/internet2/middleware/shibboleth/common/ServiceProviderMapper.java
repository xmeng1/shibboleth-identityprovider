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

package edu.internet2.middleware.shibboleth.common;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import edu.internet2.middleware.shibboleth.idp.IdPConfig;
import edu.internet2.middleware.shibboleth.metadata.EntitiesDescriptor;
import edu.internet2.middleware.shibboleth.metadata.Metadata;
import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;

/**
 * Class for determining the effective relying party from the unique id of the service provider. Checks first for an
 * exact match on the service provider, then for membership in a group of providers (perhaps a federation). Uses the
 * default relying party if neither is found.
 * 
 * @author Walter Hoehn
 */
public class ServiceProviderMapper {

	private static Logger log = Logger.getLogger(ServiceProviderMapper.class.getName());
	protected Map relyingParties = new HashMap();
	private Metadata metaData;
	private IdPConfig configuration;
	private Credentials credentials;
	private NameMapper nameMapper;

	public ServiceProviderMapper(Element rawConfig, IdPConfig configuration, Credentials credentials,
			NameMapper nameMapper) throws ServiceProviderMapperException {

		this.configuration = configuration;
		this.credentials = credentials;
		this.nameMapper = nameMapper;

		NodeList itemElements = rawConfig.getElementsByTagNameNS(IdPConfig.configNameSpace, "RelyingParty");

		for (int i = 0; i < itemElements.getLength(); i++) {
			addRelyingParty((Element) itemElements.item(i));
		}

		verifyDefaultParty(configuration);

	}

	public void setMetadata(Metadata metadata) {

		this.metaData = metadata;
	}

	private IdPConfig getOriginConfig() {

		return configuration;
	}

	protected void verifyDefaultParty(IdPConfig configuration) throws ServiceProviderMapperException {

		// Verify we have a proper default party
		String defaultParty = configuration.getDefaultRelyingPartyName();
		if (defaultParty == null || defaultParty.equals("")) {
			if (relyingParties.size() != 1) {
				log
						.error("Default Relying Party not specified.  Add a (defaultRelyingParty) attribute to <IdPConfig>.");
				throw new ServiceProviderMapperException("Required configuration not specified.");
			} else {
				log.debug("Only one Relying Party loaded.  Using this as the default.");
			}
		}
		log.debug("Default Relying Party set to: (" + defaultParty + ").");
		if (!relyingParties.containsKey(defaultParty)) {
			log.error("Default Relying Party refers to a Relying Party that has not been loaded.");
			throw new ServiceProviderMapperException("Invalid configuration (Default Relying Party).");
		}
	}

	protected RelyingParty getRelyingPartyImpl(String providerIdFromTarget) {

		// Null request, send the default
		if (providerIdFromTarget == null) {
			RelyingParty relyingParty = getDefaultRelyingParty();
			log.info("Using default Relying Party: (" + relyingParty.getName() + ").");
			return new UnknownProviderWrapper(relyingParty, providerIdFromTarget);
		}

		// Look for a configuration for the specific relying party
		if (relyingParties.containsKey(providerIdFromTarget)) {
			log.info("Found Relying Party for (" + providerIdFromTarget + ").");
			return (RelyingParty) relyingParties.get(providerIdFromTarget);
		}

		// Next, check to see if the relying party is in any groups
		RelyingParty groupParty = findRelyingPartyByGroup(providerIdFromTarget);
		if (groupParty != null) {
			log.info("Provider is a member of Relying Party (" + groupParty.getName() + ").");
			return new RelyingPartyGroupWrapper(groupParty, providerIdFromTarget);
		}

		// OK, we can't find it... just send the default
		RelyingParty relyingParty = getDefaultRelyingParty();
		log.info("Could not locate Relying Party configuration for (" + providerIdFromTarget
				+ ").  Using default Relying Party: (" + relyingParty.getName() + ").");
		return new UnknownProviderWrapper(relyingParty, providerIdFromTarget);
	}

	private RelyingParty findRelyingPartyByGroup(String providerIdFromTarget) {

		if (metaData == null) { return null; }

		EntityDescriptor provider = metaData.lookup(providerIdFromTarget);
		if (provider != null) {
			EntitiesDescriptor parent = provider.getEntitiesDescriptor();
			while (parent != null) {
				if (relyingParties.containsKey(parent.getName())) {
					log.info("Found matching Relying Party for group (" + parent.getName() + ").");
					return (RelyingParty) relyingParties.get(parent.getName());
				} else {
					log.debug("Provider is a member of group (" + parent.getName()
							+ "), but no matching Relying Party was found.");
				}
				parent = parent.getEntitiesDescriptor();
			}
		}
		return null;
	}

	public RelyingParty getDefaultRelyingParty() {

		// If there is no explicit default, pick the single configured Relying
		// Party
		String defaultParty = getOriginConfig().getDefaultRelyingPartyName();
		if (defaultParty == null || defaultParty.equals("")) { return (RelyingParty) relyingParties.values().iterator()
				.next(); }

		// If we do have a default specified, use it...
		return (RelyingParty) relyingParties.get(defaultParty);
	}

	/**
	 * Returns the relying party for a legacy provider(the default)
	 */
	public RelyingParty getLegacyRelyingParty() {

		RelyingParty relyingParty = getDefaultRelyingParty();
		log.info("Request is from legacy shib target.  Selecting default Relying Party: (" + relyingParty.getName()
				+ ").");
		return new LegacyWrapper((RelyingParty) relyingParty);

	}

	/**
	 * Returns the appropriate relying party for the supplied service provider id.
	 */
	public RelyingParty getRelyingParty(String providerIdFromTarget) {

		if (providerIdFromTarget == null || providerIdFromTarget.equals("")) {
			RelyingParty relyingParty = getDefaultRelyingParty();
			log.info("Selecting default Relying Party: (" + relyingParty.getName() + ").");
			return new NoMetadataWrapper((RelyingParty) relyingParty);
		}

		return (RelyingParty) getRelyingPartyImpl(providerIdFromTarget);
	}

	private void addRelyingParty(Element e) throws ServiceProviderMapperException {

		log.debug("Found a Relying Party.");
		try {
			if (e.getLocalName().equals("RelyingParty")) {
				RelyingParty party = new RelyingPartyImpl(e, configuration, credentials, nameMapper);
				log.debug("Relying Party (" + party.getName() + ") loaded.");
				relyingParties.put(party.getName(), party);
			}
		} catch (ServiceProviderMapperException exc) {
			log.error("Encountered an error while attempting to load Relying Party configuration.  Skipping...");
		}

	}

	/**
	 * Base relying party implementation.
	 * 
	 * @author Walter Hoehn
	 */
	protected class RelyingPartyImpl implements RelyingParty {

		private RelyingPartyIdentityProvider identityProvider;
		private String name;
		private String overridenOriginProviderId;
		private URL overridenAAUrl;
		private URI overridenDefaultAuthMethod;
		private String hsNameFormatId;
		private IdPConfig configuration;
		private boolean overridenPassThruErrors = false;
		private boolean passThruIsOverriden = false;
		private boolean forceAttributePush = false;
		private boolean forceAttributeNoPush = false;
		private boolean defaultToPOST = true;
		private boolean wantsAssertionsSigned = false;
		private int preferredArtifactType = 1;
		private String defaultTarget;

		public RelyingPartyImpl(Element partyConfig, IdPConfig globalConfig, Credentials credentials,
				NameMapper nameMapper) throws ServiceProviderMapperException {

			configuration = globalConfig;

			// Get party name
			name = ((Element) partyConfig).getAttribute("name");
			if (name == null || name.equals("")) {
				log.error("Relying Party name not set.  Add a (name) attribute to <RelyingParty>.");
				throw new ServiceProviderMapperException("Required configuration not specified.");
			}
			log.debug("Loading Relying Party: (" + name + ").");

			// Process overrides for global configuration data
			String attribute = ((Element) partyConfig).getAttribute("providerId");
			if (attribute != null && !attribute.equals("")) {
				log.debug("Overriding providerId for Relying Pary (" + name + ") with (" + attribute + ").");
				overridenOriginProviderId = attribute;
			}

			attribute = ((Element) partyConfig).getAttribute("AAUrl");
			if (attribute != null && !attribute.equals("")) {
				log.debug("Overriding AAUrl for Relying Pary (" + name + ") with (" + attribute + ").");
				try {
					overridenAAUrl = new URL(attribute);
				} catch (MalformedURLException e) {
					log.error("(AAUrl) attribute to is not a valid URL.");
					throw new ServiceProviderMapperException("Configuration is invalid.");
				}
			}

			attribute = ((Element) partyConfig).getAttribute("defaultAuthMethod");
			if (attribute != null && !attribute.equals("")) {
				log.debug("Overriding defaultAuthMethod for Relying Pary (" + name + ") with (" + attribute + ").");
				try {
					overridenDefaultAuthMethod = new URI(attribute);
				} catch (URISyntaxException e1) {
					log.error("(defaultAuthMethod) attribute to is not a valid URI.");
					throw new ServiceProviderMapperException("Configuration is invalid.");
				}
			}

			attribute = ((Element) partyConfig).getAttribute("passThruErrors");
			if (attribute != null && !attribute.equals("")) {
				log.debug("Overriding passThruErrors for Relying Pary (" + name + ") with (" + attribute + ").");
				overridenPassThruErrors = Boolean.valueOf(attribute).booleanValue();
				passThruIsOverriden = true;
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
				log.debug("Overriding AAUrl for Relying Pary (" + name + ") with (" + attribute + ").");
				try {
					preferredArtifactType = Integer.parseInt(attribute);
				} catch (NumberFormatException e) {
					log.error("(preferredArtifactType) attribute to is not a valid integer.");
					throw new ServiceProviderMapperException("Configuration is invalid.");
				}
				log.debug("Preferred artifact type: (" + preferredArtifactType + ").");
			}

			// Load and verify the name format that the HS should use in
			// assertions for this RelyingParty
			NodeList hsNameFormats = ((Element) partyConfig).getElementsByTagNameNS(IdPConfig.configNameSpace,
					"HSNameFormat");
			// If no specification. Make sure we have a default mapping
			if (hsNameFormats.getLength() < 1) {
				if (nameMapper.getNameIdentifierMappingById(null) == null) {
					log.error("Relying Party HS Name Format not set.  Add a <HSNameFormat> element to <RelyingParty>.");
					throw new ServiceProviderMapperException("Required configuration not specified.");
				}

			} else {
				// We do have a specification, so make sure it points to a
				// valid Name Mapping
				if (hsNameFormats.getLength() > 1) {
					log.warn("Found multiple HSNameFormat specifications for Relying Party (" + name
							+ ").  Ignoring all but the first.");
				}

				hsNameFormatId = ((Element) hsNameFormats.item(0)).getAttribute("nameMapping");
				if (hsNameFormatId == null || hsNameFormatId.equals("")) {
					log.error("HS Name Format mapping not set.  Add a (nameMapping) attribute to <HSNameFormat>.");
					throw new ServiceProviderMapperException("Required configuration not specified.");
				}

				if (nameMapper.getNameIdentifierMappingById(hsNameFormatId) == null) {
					log.error("Relying Party HS Name Format refers to a name mapping that is not loaded.");
					throw new ServiceProviderMapperException("Required configuration not specified.");
				}
			}

			// Load the credential for signing
			String credentialName = ((Element) partyConfig).getAttribute("signingCredential");
			Credential signingCredential = credentials.getCredential(credentialName);
			if (signingCredential == null) {
				if (credentialName == null || credentialName.equals("")) {
					log.error("Relying Party credential not set.  Add a (signingCredential) "
							+ "attribute to <RelyingParty>.");
					throw new ServiceProviderMapperException("Required configuration not specified.");
				} else {
					log.error("Relying Party credential invalid.  Fix the (signingCredential) attribute "
							+ "on <RelyingParty>.");
					throw new ServiceProviderMapperException("Required configuration is invalid.");
				}

			}

			// Initialize and Identity Provider object for this use by this relying party
			identityProvider = new RelyingPartyIdentityProvider(overridenOriginProviderId != null
					? overridenOriginProviderId
					: configuration.getProviderId(), signingCredential);

		}

		public String getProviderId() {

			return name;
		}

		public String getName() {

			return name;
		}

		public IdentityProvider getIdentityProvider() {

			return identityProvider;
		}

		public boolean isLegacyProvider() {

			return false;
		}

		public String getHSNameFormatId() {

			return hsNameFormatId;
		}

		public URI getDefaultAuthMethod() {

			if (overridenDefaultAuthMethod != null) {
				return overridenDefaultAuthMethod;
			} else {
				return configuration.getDefaultAuthMethod();
			}
		}

		public URL getAAUrl() {

			if (overridenAAUrl != null) {
				return overridenAAUrl;
			} else {
				return configuration.getAAUrl();
			}
		}

		public boolean passThruErrors() {

			if (passThruIsOverriden) {
				return overridenPassThruErrors;
			} else {
				return configuration.passThruErrors();
			}
		}

		public boolean forceAttributePush() {

			return forceAttributePush;
		}

		public boolean forceAttributeNoPush() {

			return forceAttributeNoPush;
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

	/**
	 * Relying party implementation wrapper for relying parties that are groups.
	 * 
	 * @author Walter Hoehn
	 */
	class RelyingPartyGroupWrapper implements RelyingParty {

		private RelyingParty wrapped;
		private String providerId;

		RelyingPartyGroupWrapper(RelyingParty wrapped, String providerId) {

			this.wrapped = wrapped;
			this.providerId = providerId;
		}

		public String getName() {

			return wrapped.getName();
		}

		public boolean isLegacyProvider() {

			return false;
		}

		public IdentityProvider getIdentityProvider() {

			return wrapped.getIdentityProvider();
		}

		public String getProviderId() {

			return providerId;
		}

		public String getHSNameFormatId() {

			return wrapped.getHSNameFormatId();
		}

		public URL getAAUrl() {

			return wrapped.getAAUrl();
		}

		public URI getDefaultAuthMethod() {

			return wrapped.getDefaultAuthMethod();
		}

		public boolean passThruErrors() {

			return wrapped.passThruErrors();
		}

		public boolean forceAttributePush() {

			return wrapped.forceAttributePush();
		}

		public boolean forceAttributeNoPush() {

			return wrapped.forceAttributeNoPush();
		}

		public boolean defaultToPOSTProfile() {

			return wrapped.defaultToPOSTProfile();
		}

		public boolean wantsAssertionsSigned() {

			return wrapped.wantsAssertionsSigned();
		}

		public int getPreferredArtifactType() {

			return wrapped.getPreferredArtifactType();
		}

		public String getDefaultTarget() {

			return wrapped.getDefaultTarget();
		}
	}

	/**
	 * Relying party implementation wrapper for anonymous service providers.
	 * 
	 * @author Walter Hoehn
	 */
	protected class UnknownProviderWrapper implements RelyingParty {

		protected RelyingParty wrapped;
		protected String providerId;

		protected UnknownProviderWrapper(RelyingParty wrapped, String providerId) {

			this.wrapped = wrapped;
			this.providerId = providerId;
		}

		public String getName() {

			return wrapped.getName();
		}

		public IdentityProvider getIdentityProvider() {

			return wrapped.getIdentityProvider();
		}

		public String getProviderId() {

			return providerId;
		}

		public String getHSNameFormatId() {

			return wrapped.getHSNameFormatId();
		}

		public boolean isLegacyProvider() {

			return wrapped.isLegacyProvider();
		}

		public URL getAAUrl() {

			return wrapped.getAAUrl();
		}

		public URI getDefaultAuthMethod() {

			return wrapped.getDefaultAuthMethod();
		}

		public boolean passThruErrors() {

			return wrapped.passThruErrors();
		}

		public boolean forceAttributePush() {

			return false;
		}

		public boolean forceAttributeNoPush() {

			return false;
		}

		public boolean defaultToPOSTProfile() {

			return true;
		}

		public boolean wantsAssertionsSigned() {

			return wrapped.wantsAssertionsSigned();
		}

		public int getPreferredArtifactType() {

			return wrapped.getPreferredArtifactType();
		}

		public String getDefaultTarget() {

			return wrapped.getDefaultTarget();
		}
	}

	/**
	 * Relying party wrapper for Shibboleth &lt;=1.1 service providers.
	 * 
	 * @author Walter Hoehn
	 */
	class LegacyWrapper extends UnknownProviderWrapper implements RelyingParty {

		LegacyWrapper(RelyingParty wrapped) {

			super(wrapped, null);
		}

		public boolean isLegacyProvider() {

			return true;
		}

		public String getHSNameFormatId() {

			return ((RelyingParty) wrapped).getHSNameFormatId();
		}

		public URL getAAUrl() {

			return ((RelyingParty) wrapped).getAAUrl();
		}

		public URI getDefaultAuthMethod() {

			return ((RelyingParty) wrapped).getDefaultAuthMethod();
		}
	}

	/**
	 * Relying party wrapper for providers for which we have no metadata
	 * 
	 * @author Walter Hoehn
	 */
	class NoMetadataWrapper extends UnknownProviderWrapper implements RelyingParty {

		NoMetadataWrapper(RelyingParty wrapped) {

			super(wrapped, null);
		}

		public String getHSNameFormatId() {

			return ((RelyingParty) wrapped).getHSNameFormatId();
		}

		public URL getAAUrl() {

			return ((RelyingParty) wrapped).getAAUrl();
		}

		public URI getDefaultAuthMethod() {

			return ((RelyingParty) wrapped).getDefaultAuthMethod();
		}
	}
}