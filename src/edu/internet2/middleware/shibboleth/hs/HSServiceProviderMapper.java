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
package edu.internet2.middleware.shibboleth.hs;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import edu.internet2.middleware.shibboleth.common.Credential;
import edu.internet2.middleware.shibboleth.common.Credentials;
import edu.internet2.middleware.shibboleth.common.RelyingParty;
import edu.internet2.middleware.shibboleth.common.ServiceProviderMapper;
import edu.internet2.middleware.shibboleth.common.ServiceProviderMapperException;
import edu.internet2.middleware.shibboleth.common.ShibbolethOriginConfig;

/**
 * Class for determining the effective relying party for the Shibboleth handle service from the unique id of the service
 * provider.
 *
 * @author Walter Hoehn
 */
public class HSServiceProviderMapper extends ServiceProviderMapper {

	private static Logger log = Logger.getLogger(HSServiceProviderMapper.class.getName());
	private HSConfig configuration;
	private Credentials credentials;
	private HSNameMapper nameMapper;

	/**
         * Constructs a new service provider mapper for the handle service.
	 * 
	 * @param rawConfig DOM representation of the handle service configuration
	 * @param configuration global handle service configuration
	 * @param credentials credentials for the handle service using this provider mapper
	 * @param nameMapper name mapper for the handle service using this provider mapper
         *
	 * @throws ServiceProviderMapperException
	 *             if the configuration is invalid
	 */
	public HSServiceProviderMapper(
		Element rawConfig,
		HSConfig configuration,
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

		verifyDefaultParty(configuration);
	}

	private void addRelyingParty(Element e) throws ServiceProviderMapperException {

		log.debug("Found a Relying Party.");
		try {
			if (e.getLocalName().equals("RelyingParty")) {
				RelyingParty party = new HSRelyingPartyImpl(e, configuration, credentials, nameMapper);
				log.debug("Relying Party (" + party.getName() + ") loaded.");
				relyingParties.put(party.getName(), party);
			}
		} catch (ServiceProviderMapperException exc) {
			log.error("Encountered an error while attempting to load Relying Party configuration.  Skipping...");
		}
	}

        /**
         * Returns the appropriate relying party for the supplied service provider id.
         */
	public HSRelyingParty getRelyingParty(String providerIdFromTarget) {

		//If the target did not send a Provider Id, then assume it is a Shib
		// 1.1 or older target
		if (providerIdFromTarget == null || providerIdFromTarget.equals("")) {
			log.info("Request is from legacy shib target.  Selecting default Relying Party.");
			return new LegacyWrapper((HSRelyingParty) getDefaultRelyingPatry());
		}

		return (HSRelyingParty) getRelyingPartyImpl(providerIdFromTarget);
	}

	protected ShibbolethOriginConfig getOriginConfig() {
		return configuration;
	}

        /**
         * HS-specific relying party implementation.
         * @author Walter Hoehn
         */
	class HSRelyingPartyImpl extends BaseRelyingPartyImpl implements HSRelyingParty {

		private URL overridenAAUrl;
		private URI overridenDefaultAuthMethod;
		protected String hsNameFormatId;
		private HSConfig configuration;

		HSRelyingPartyImpl(
			Element partyConfig,
			HSConfig globalConfig,
			Credentials credentials,
			HSNameMapper nameMapper)
			throws ServiceProviderMapperException {

			super(partyConfig);

			configuration = globalConfig;

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

			//Global overrides
			String attribute = ((Element) partyConfig).getAttribute("AAUrl");
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

			identityProvider =
				new RelyingPartyIdentityProvider(
					overridenOriginProviderId != null ? overridenOriginProviderId : configuration.getProviderId(),
					credential);
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
	}

        /**
         * Relying party wrapper for Shibboleth &lt;=1.1 service providers.
         * @author Walter Hoehn
         */
	class LegacyWrapper extends UnknownProviderWrapper implements HSRelyingParty {

		LegacyWrapper(HSRelyingParty wrapped) {
			super(wrapped);
		}
		public boolean isLegacyProvider() {
			return true;
		}

		public String getHSNameFormatId() {
			return ((HSRelyingParty) wrapped).getHSNameFormatId();
		}

		public URL getAAUrl() {
			return ((HSRelyingParty) wrapped).getAAUrl();
		}

		public URI getDefaultAuthMethod() {
			return ((HSRelyingParty) wrapped).getDefaultAuthMethod();
		}
	}

}
