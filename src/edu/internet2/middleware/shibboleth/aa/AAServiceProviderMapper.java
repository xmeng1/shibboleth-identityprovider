/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the
 * above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution, if any, must include the following acknowledgment: "This product includes
 * software developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu> Internet2
 * Project. Alternately, this acknowledegement may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear. Neither the name of Shibboleth nor the names of its contributors, nor Internet2,
 * nor the University Corporation for Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote
 * products derived from this software without specific prior written permission. For written permission, please
 * contact shibboleth@shibboleth.org Products derived from this software may not be called Shibboleth, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor may Shibboleth appear in their name,
 * without prior written permission of the University Corporation for Advanced Internet Development. THIS SOFTWARE IS
 * PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND
 * NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS
 * WITH LICENSEE. IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY CORPORATION FOR ADVANCED
 * INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.aa;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import edu.internet2.middleware.shibboleth.common.Credential;
import edu.internet2.middleware.shibboleth.common.Credentials;
import edu.internet2.middleware.shibboleth.common.RelyingParty;
import edu.internet2.middleware.shibboleth.common.ServiceProviderMapper;
import edu.internet2.middleware.shibboleth.common.ServiceProviderMapperException;
import edu.internet2.middleware.shibboleth.common.ShibbolethOriginConfig;
import edu.internet2.middleware.shibboleth.metadata.Metadata;

/**
 * Class for determining the effective relying party for the Shibboleth attribute authority from the unique id of the
 * service provider.
 * 
 * @author Walter Hoehn
 */
public class AAServiceProviderMapper extends ServiceProviderMapper {

	private static Logger	log	= Logger.getLogger(AAServiceProviderMapper.class.getName());
	private AAConfig		configuration;
	private Credentials		credentials;

	/**
	 * Constructs a new service provider mapper for the attribute authority.
	 * 
	 * @param rawConfig
	 *            DOM representation of the attribute authority configuration
	 * @param configuration
	 *            global attribute authority configuration
	 * @throws ServiceProviderMapperException
	 *             if the configuration is invalid
	 */
	public AAServiceProviderMapper(Element rawConfig, AAConfig configuration, Credentials credentials, Metadata metaData)
			throws ServiceProviderMapperException {
		super(metaData);
		this.configuration = configuration;
		this.credentials = credentials;

		NodeList itemElements = rawConfig.getElementsByTagNameNS(ShibbolethOriginConfig.originConfigNamespace,
				"RelyingParty");

		for (int i = 0; i < itemElements.getLength(); i++) {
			addRelyingParty((Element) itemElements.item(i));
		}

		verifyDefaultParty(configuration);
	}

	private void addRelyingParty(Element e) throws ServiceProviderMapperException {

		log.debug("Found a Relying Party.");
		try {
			if (e.getLocalName().equals("RelyingParty")) {
				RelyingParty party = new AARelyingPartyImpl(e, configuration, credentials);
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
	public AARelyingParty getRelyingParty(String providerIdFromTarget) {
		return (AARelyingParty) getRelyingPartyImpl(providerIdFromTarget);
	}

	protected ShibbolethOriginConfig getOriginConfig() {
		return configuration;
	}

	/**
	 * AA-specific relying party implementation.
	 * 
	 * @author Walter Hoehn
	 */
	class AARelyingPartyImpl extends BaseRelyingPartyImpl implements AARelyingParty {

		private AAConfig	aaConfig;
		private boolean		overridenPassThruErrors	= false;
		private boolean		passThruIsOverriden		= false;

		public AARelyingPartyImpl(Element partyConfig, AAConfig globalConfig, Credentials credentials)
				throws ServiceProviderMapperException {
			super(partyConfig);

			aaConfig = globalConfig;

			String attribute = ((Element) partyConfig).getAttribute("passThruErrors");
			if (attribute != null && !attribute.equals("")) {
				log.debug("Overriding passThruErrors for Relying Pary (" + name + ") with (" + attribute + ").");
				overridenPassThruErrors = Boolean.valueOf(attribute).booleanValue();
				passThruIsOverriden = true;
			}

			//Load a credential for signing if we need it
			boolean signAttrResponses = new Boolean(((Element) partyConfig).getAttribute("signAttrResponses"))
					.booleanValue();
			boolean signAttrAssertions = new Boolean(((Element) partyConfig).getAttribute("signAttrAssertions"))
					.booleanValue();

			Credential credential = null;
			if (signAttrAssertions || signAttrResponses) {

				String credentialName = ((Element) partyConfig).getAttribute("AASigningCredential");
				if (credentialName == null || credentialName.equals("")) {
					credentialName = ((Element) partyConfig).getAttribute("signingCredential");
				} else {
					log.debug("Using (AASigningCredential) for AA signing.");
				}

				credential = credentials.getCredential(credentialName);
				if ((credential == null) && (signAttrResponses || signAttrAssertions)) {
					if (credentialName == null || credentialName.equals("")) {
						log
								.error("Relying Party credential not set.  Add a (AASigningCredential) or (signingCredential) attribute to <RelyingParty>.");
						throw new ServiceProviderMapperException("Required configuration not specified.");
					} else {
						log
								.error("Relying Party credential invalid.  Fix the (signingCredential) attribute on <RelyingParty>.");
						throw new ServiceProviderMapperException("Required configuration is invalid.");
					}
				}

			}

			identityProvider = new RelyingPartyIdentityProvider(overridenOriginProviderId != null
					? overridenOriginProviderId
					: configuration.getProviderId(), signAttrResponses ? credential : null, signAttrAssertions
					? credential
					: null);
		}

		public boolean passThruErrors() {
			if (passThruIsOverriden) {
				return overridenPassThruErrors;
			} else {
				return aaConfig.passThruErrors();
			}
		}

	}
}
