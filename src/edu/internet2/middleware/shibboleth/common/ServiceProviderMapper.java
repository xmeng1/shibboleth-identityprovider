/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation
 * for Advanced Internet Development, Inc. All rights reserved
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
 * <http://www.ucaid.edu> Internet2 Project. Alternately, this acknowledegement
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
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package edu.internet2.middleware.shibboleth.common;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import edu.internet2.middleware.shibboleth.hs.HSNameMapper;

/**
 * @author Walter Hoehn
 *  
 */
public class ServiceProviderMapper {

	private static Logger log = Logger.getLogger(ShibbolethOriginConfig.class.getName());
	private ShibbolethOriginConfig configuration;
	private Credentials credentials;
	private HSNameMapper nameMapper;
	private Map relyingParties = new HashMap();

	public ServiceProviderMapper(
		Element rawConfig,
		ShibbolethOriginConfig configuration,
		Credentials credentials,
		HSNameMapper nameMapper)
		throws ServiceProviderMapperException {

		this.configuration = configuration;
		this.credentials = credentials;
		this.nameMapper = nameMapper;

		NodeList itemElements =
			rawConfig.getElementsByTagNameNS(ShibbolethOriginConfig.originConfigNamespace, "RelyingParty");

		for (int i = 0; i < itemElements.getLength(); i++) {
			addRelyingParty((Element) itemElements.item(i));
		}

		//Verify we have a proper default party
		String defaultParty =
			configuration.getConfigProperty(
				"edu.internet2.middleware.shibboleth.common.RelyingParty.defaultRelyingParty");
		if (defaultParty == null || defaultParty.equals("")) {
			if (relyingParties.size() != 1) {
				log.error(
					"Default Relying Party not specified.  Add a (defaultRelyingParty) attribute to <ShibbolethOriginConfig>.");
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
	public RelyingParty getRelyingParty(String providerIdFromTarget) {

		//If the target did not send a Provider Id, then assume it is a Shib
		// 1.1 or older target
		if (providerIdFromTarget == null || providerIdFromTarget.equals("")) {
			log.info("Request is from legacy shib target.  Selecting default Relying Party.");
			return new LegacyWrapper(getDefaultRelyingPatry());
		}

		//Look for a configuration for the specific relying party
		if (relyingParties.containsKey(providerIdFromTarget)) {
			log.info("Found Relying Party for (" + providerIdFromTarget + ").");
			return (RelyingParty) relyingParties.get(providerIdFromTarget);
		}

		//Next, check to see if the relying party is in any groups
		RelyingParty groupParty = findRelyingPartyByGroup(providerIdFromTarget);
		if (groupParty != null) {
			log.info("Provider is a member of Relying Party (" + groupParty.getName() + ").");
			return new RelyingPartyGroupWrapper(groupParty, providerIdFromTarget);
		}

		//OK, just send the default
		log.info(
			"Could not locate Relying Party configuration for ("
				+ providerIdFromTarget
				+ ").  Using default Relying Party.");
		return new UnknownProviderWrapper(getDefaultRelyingPatry());
	}

	private RelyingParty findRelyingPartyByGroup(String providerIdFromTarget) {

		// TODO This is totally a stub and needs to be based on target metadata
		// lookup
		if (providerIdFromTarget.startsWith("urn:mace:inqueue:")) {
			if (relyingParties.containsKey("urn:mace:inqueue")) {
				return (RelyingParty) relyingParties.get("urn:mace:inqueue");
			}
		}
		return null;
	}

	private RelyingParty getDefaultRelyingPatry() {

		//If there is no explicit default, pick the single configured Relying
		// Party
		String defaultParty =
			configuration.getConfigProperty(
				"edu.internet2.middleware.shibboleth.common.RelyingParty.defaultRelyingParty");
		if (defaultParty == null || defaultParty.equals("")) {
			return (RelyingParty) relyingParties.values().iterator().next();
		}

		//If we do have a default specified, use it...
		return (RelyingParty) relyingParties.get(defaultParty);
	}

	class RelyingPartyImpl implements RelyingParty {

		protected ShibbolethOriginConfig originConfig;
		protected Properties partyOverrides = new Properties();
		protected RelyingPartyIdentityProvider identityProvider;
		protected String name;
		protected String hsNameFormatId;

		public RelyingPartyImpl(
			Element partyConfig,
			ShibbolethOriginConfig globalConfig,
			Credentials credentials,
			HSNameMapper nameMapper)
			throws ServiceProviderMapperException {

			//Use global config for defaults
			this.originConfig = globalConfig;

			//Get party name
			name = ((Element) partyConfig).getAttribute("name");
			if (name == null || name.equals("")) {
				log.error("Relying Party name not set.  Add a (name) attribute to <RelyingParty>.");
				throw new ServiceProviderMapperException("Required configuration not specified.");
			}
			log.debug("Loading Relying Party: (" + name + ").");

			//Load a credential for signing
			String credentialName = ((Element) partyConfig).getAttribute("signingCredential");
			Credential credential = credentials.getCredential(credentialName);

			if (credential == null) {
				if (credentialName == null || credentialName.equals("")) {
					log.error(
						"Relying Party credential not set.  Add a (signingCredential) attribute to <RelyingParty>.");
					throw new ServiceProviderMapperException("Required configuration not specified.");
				} else {
					log.error(
						"Relying Party credential not set.  Add a (signingCredential) attribute to <RelyingParty>.");
					throw new ServiceProviderMapperException("Required configuration not specified.");
				}
			}

			//Load and verify the name format that the HS should use in
			//assertions for this RelyingParty
			NodeList hsNameFormats =
				((Element) partyConfig).getElementsByTagNameNS(
					ShibbolethOriginConfig.originConfigNamespace,
					"HSNameFormat");
			//If no specification. Make sure we have a default mapping
			if (hsNameFormats.getLength() < 1) {
				if (nameMapper.getNameIdentifierMappingById(null) == null) {
					log.error("Relying Party HS Name Format not set.  Add a <HSNameFormat> element to <RelyingParty>.");
					throw new ServiceProviderMapperException("Required configuration not specified.");
				}

			} else {
				//We do have a specification, so make sure it points to a
				// valid Name Mapping
				if (hsNameFormats.getLength() > 1) {
					log.warn(
						"Found multiple HSNameFormat specifications for Relying Party ("
							+ name
							+ ").  Ignoring all but the first.");
				}

				String hsNameFormatId = ((Element) hsNameFormats.item(0)).getAttribute("nameMapping");
				if (hsNameFormatId == null || hsNameFormatId.equals("")) {
					log.error("HS Name Format mapping not set.  Add a (nameMapping) attribute to <HSNameFormat>.");
					throw new ServiceProviderMapperException("Required configuration not specified.");
				}

				if (nameMapper.getNameIdentifierMappingById(hsNameFormatId) == null) {
					log.error("Relying Party HS Name Format refers to a name mapping that is not loaded.");
					throw new ServiceProviderMapperException("Required configuration not specified.");
				}
			}

			//Process overrides for global data
			String attribute = ((Element) partyConfig).getAttribute("providerId");
			if (attribute != null && !attribute.equals("")) {
				log.debug("Overriding providerId for Relying Pary (" + name + ") with (" + attribute + ").");
				partyOverrides.setProperty(
					"edu.internet2.middleware.shibboleth.hs.HandleServlet.providerId",
					attribute);
			}

			attribute = ((Element) partyConfig).getAttribute("AAUrl");
			if (attribute != null && !attribute.equals("")) {
				log.debug("Overriding AAUrl for Relying Pary (" + name + ") with (" + attribute + ").");
				partyOverrides.setProperty("edu.internet2.middleware.shibboleth.hs.HandleServlet.AAUrl", attribute);
			}

			identityProvider =
				new RelyingPartyIdentityProvider(
					getConfigProperty("edu.internet2.middleware.shibboleth.hs.HandleServlet.providerId"),
					credential);
		}

		public String getProviderId() {
			return name;
		}

		public String getName() {
			return name;
		}

		public boolean isLegacyProvider() {
			return false;
		}

		public String getConfigProperty(String key) {
			if (partyOverrides.containsKey(key)) {
				return partyOverrides.getProperty(key);
			}
			return originConfig.getConfigProperty(key);
		}

		public String getHSNameFormatId() {
			return null;
		}

		public IdentityProvider getIdentityProvider() {
			return identityProvider;
		}

		class RelyingPartyIdentityProvider implements IdentityProvider {

			private String providerId;
			private Credential responseSigningCredential;

			RelyingPartyIdentityProvider(String providerId, Credential responseSigningCred) {
				this.providerId = providerId;
				this.responseSigningCredential = responseSigningCred;
			}

			public String getProviderId() {
				return providerId;
			}

			public Credential getResponseSigningCredential() {
				return responseSigningCredential;
			}

			public Credential getAssertionSigningCredential() {
				return null;
			}

		}
	}

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

		public String getConfigProperty(String key) {
			return wrapped.getConfigProperty(key);
		}

		public boolean isLegacyProvider() {
			return false;
		}

		public String getHSNameFormatId() {
			return wrapped.getHSNameFormatId();
		}

		public IdentityProvider getIdentityProvider() {
			return wrapped.getIdentityProvider();
		}

		public String getProviderId() {
			return providerId;
		}
	}

	class UnknownProviderWrapper implements RelyingParty {
		private RelyingParty wrapped;

		UnknownProviderWrapper(RelyingParty wrapped) {
			this.wrapped = wrapped;
		}

		public String getName() {
			return wrapped.getName();
		}

		public String getConfigProperty(String key) {
			return wrapped.getConfigProperty(key);
		}

		public boolean isLegacyProvider() {
			return wrapped.isLegacyProvider();
		}

		public String getHSNameFormatId() {
			return wrapped.getHSNameFormatId();
		}

		public IdentityProvider getIdentityProvider() {
			return wrapped.getIdentityProvider();
		}

		public String getProviderId() {
			return null;
		}
	}

	class LegacyWrapper extends UnknownProviderWrapper {

		LegacyWrapper(RelyingParty wrapped) {
			super(wrapped);
		}
		public boolean isLegacyProvider() {
			return true;
		}
	}
}
