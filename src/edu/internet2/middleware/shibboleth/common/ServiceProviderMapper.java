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

package edu.internet2.middleware.shibboleth.common;

import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.AARelyingParty;
import edu.internet2.middleware.shibboleth.hs.HSRelyingParty;

/**
 * Base class for determining the effective relying party from the unique id of the service provider. Checks first for
 * an exact match on the service provider, then for membership in a federation. Uses the default relying party if
 * neither is found.
 * 
 * @author Walter Hoehn
 */
public abstract class ServiceProviderMapper {

	private static Logger	log				= Logger.getLogger(ServiceProviderMapper.class.getName());
	protected Map			relyingParties	= new HashMap();

	protected abstract ShibbolethOriginConfig getOriginConfig();

	protected void verifyDefaultParty(ShibbolethOriginConfig configuration) throws ServiceProviderMapperException {
		//Verify we have a proper default party
		String defaultParty = configuration.getDefaultRelyingPartyName();
		if (defaultParty == null || defaultParty.equals("")) {
			if (relyingParties.size() != 1) {
				log
						.error("Default Relying Party not specified.  Add a (defaultRelyingParty) attribute to <ShibbolethOriginConfig>.");
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
		log.info("Could not locate Relying Party configuration for (" + providerIdFromTarget
				+ ").  Using default Relying Party.");
		return new UnknownProviderWrapper(getDefaultRelyingPatry(), providerIdFromTarget);
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

	protected RelyingParty getDefaultRelyingPatry() {

		//If there is no explicit default, pick the single configured Relying
		// Party
		String defaultParty = getOriginConfig().getDefaultRelyingPartyName();
		if (defaultParty == null || defaultParty.equals("")) {
			return (RelyingParty) relyingParties.values().iterator().next();
		}

		//If we do have a default specified, use it...
		return (RelyingParty) relyingParties.get(defaultParty);
	}

	/**
	 * Base relying party implementation.
	 * 
	 * @author Walter Hoehn
	 */
	protected abstract class BaseRelyingPartyImpl implements RelyingParty {

		protected RelyingPartyIdentityProvider	identityProvider;
		protected String						name;
		protected String						overridenOriginProviderId;

		public BaseRelyingPartyImpl(Element partyConfig) throws ServiceProviderMapperException {

			//Get party name
			name = ((Element) partyConfig).getAttribute("name");
			if (name == null || name.equals("")) {
				log.error("Relying Party name not set.  Add a (name) attribute to <RelyingParty>.");
				throw new ServiceProviderMapperException("Required configuration not specified.");
			}
			log.debug("Loading Relying Party: (" + name + ").");

			//Process overrides for global data
			String attribute = ((Element) partyConfig).getAttribute("providerId");
			if (attribute != null && !attribute.equals("")) {
				log.debug("Overriding providerId for Relying Pary (" + name + ") with (" + attribute + ").");
				overridenOriginProviderId = attribute;
			}

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

		/**
		 * Default identity provider implementation.
		 * 
		 * @author Walter Hoehn
		 */
		protected class RelyingPartyIdentityProvider implements IdentityProvider {

			private String		providerId;
			private Credential	responseSigningCredential;
			private Credential	assertionSigningCredential;

			public RelyingPartyIdentityProvider(String providerId, Credential responseSigningCred) {
				this.providerId = providerId;
				this.responseSigningCredential = responseSigningCred;
			}

			public RelyingPartyIdentityProvider(String providerId, Credential responseSigningCred,
					Credential assertionSigningCred) {
				this.providerId = providerId;
				this.responseSigningCredential = responseSigningCred;
				this.assertionSigningCredential = assertionSigningCred;
			}

			public String getProviderId() {
				return providerId;
			}

			public Credential getResponseSigningCredential() {
				return responseSigningCredential;
			}

			public Credential getAssertionSigningCredential() {
				return assertionSigningCredential;
			}

		}
	}

	/**
	 * Relying party implementation wrapper for relying parties that are federations.
	 * 
	 * @author Walter Hoehn
	 */
	class RelyingPartyGroupWrapper implements RelyingParty, HSRelyingParty, AARelyingParty {

		private RelyingParty	wrapped;
		private String			providerId;

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
			if (!(wrapped instanceof HSRelyingParty)) {
				return null;
			}
			return ((HSRelyingParty) wrapped).getHSNameFormatId();
		}

		public URL getAAUrl() {
			if (!(wrapped instanceof HSRelyingParty)) {
				return null;
			}
			return ((HSRelyingParty) wrapped).getAAUrl();
		}

		public URI getDefaultAuthMethod() {
			if (!(wrapped instanceof HSRelyingParty)) {
				return null;
			}
			return ((HSRelyingParty) wrapped).getDefaultAuthMethod();
		}

		public boolean passThruErrors() {
			if (!(wrapped instanceof AARelyingParty)) {
				return false;
			}
			return ((AARelyingParty) wrapped).passThruErrors();
		}
	}

	/**
	 * Relying party implementation wrapper for anonymous service providers.
	 * 
	 * @author Walter Hoehn
	 */
	protected class UnknownProviderWrapper implements RelyingParty, HSRelyingParty, AARelyingParty {

		protected RelyingParty	wrapped;
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
			if (!(wrapped instanceof HSRelyingParty)) {
				return null;
			}
			return ((HSRelyingParty) wrapped).getHSNameFormatId();
		}

		public boolean isLegacyProvider() {
			if (!(wrapped instanceof HSRelyingParty)) {
				return false;
			}
			return ((HSRelyingParty) wrapped).isLegacyProvider();
		}

		public URL getAAUrl() {
			if (!(wrapped instanceof HSRelyingParty)) {
				return null;
			}
			return ((HSRelyingParty) wrapped).getAAUrl();
		}

		public URI getDefaultAuthMethod() {
			if (!(wrapped instanceof HSRelyingParty)) {
				return null;
			}
			return ((HSRelyingParty) wrapped).getDefaultAuthMethod();
		}

		public boolean passThruErrors() {
			if (!(wrapped instanceof AARelyingParty)) {
				return false;
			}
			return ((AARelyingParty) wrapped).passThruErrors();
		}
	}

}
