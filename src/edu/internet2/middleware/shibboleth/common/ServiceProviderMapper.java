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

import org.w3c.dom.Element;

/**
 * @author Walter Hoehn
 *  
 */
public class ServiceProviderMapper {

	ShibbolethOriginConfig configuration;
	Credentials credentials;
	Map relyingParties = new HashMap();
	Map relyingPartyGroups = new HashMap();

	public ServiceProviderMapper(ShibbolethOriginConfig configuration, Credentials credentials) {
		this.configuration = configuration;
		this.credentials = credentials;
	}

	public void addRelyingParty(Element e) {
		if (e.getLocalName().equals("RelyingParty")) {
			RelyingParty party = new RelyingPartyImpl(e, configuration, credentials);
			relyingParties.put(party.getName(), party);
		} else if (e.getLocalName().equals("RelyingPartyGroup")) {
			RelyingParty party = new RelyingPartyImpl(e, configuration, credentials);
			relyingPartyGroups.put(party.getName(), party);
		} else {
			//TODO throw exception here
		}
	}

	public RelyingParty getRelyingParty(String providerIdFromTarget) {

		//If the target did not send a Provider Id, then assume it is a Shib
		// 1.1 or older target
		if (providerIdFromTarget == null || providerIdFromTarget.equals("")) {
			return new LegacyWrapper(getDefaultRelyingPatry());
		}

		if (!relyingParties.containsKey(providerIdFromTarget)) {
			return getDefaultRelyingPatry();
		}
		//TODO do secondary lookup for groups (metadata)
		return (RelyingParty) relyingParties.get(providerIdFromTarget);
	}

	private RelyingParty getDefaultRelyingPatry() {

		return (RelyingParty) relyingParties.get(
			configuration.getConfigProperty(
				"edu.internet2.middleware.shibboleth.common.RelyingParty.defaultRelyingParty"));
		// TODO look for groups too, probably first
	}
	class RelyingPartyImpl implements RelyingParty {

		protected ShibbolethOriginConfig originConfig;
		protected Properties partyOverrides = new Properties();
		protected RelyingPartyIdentityProvider identityProvider;
		protected String id = "test:id";

		public RelyingPartyImpl(Element partyConfig, ShibbolethOriginConfig globalConfig, Credentials credentials) {

			this.originConfig = globalConfig;
			
			
			//TODO this is just a stub... has to come from configuration
			partyOverrides.setProperty(
				"edu.internet2.middleware.shibboleth.hs.HandleServlet.responseSigningCredential",
				"foo");

			identityProvider =
				new RelyingPartyIdentityProvider(
					getConfigProperty("edu.internet2.middleware.shibboleth.hs.HandleServlet.providerId"),
					credentials.getCredential(
						getConfigProperty("edu.internet2.middleware.shibboleth.hs.HandleServlet.responseSigningCredential")));
			//TODO stub

		}

		public String getProviderId() {
			return id;
		}

		public String getName() {
			return id;
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

		RelyingPartyGroupWrapper(RelyingPartyImpl wrapped, String providerId) {
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
			return true;
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

	class LegacyWrapper implements RelyingParty {
		private RelyingParty wrapped;

		LegacyWrapper(RelyingParty wrapped) {
			this.wrapped = wrapped;
		}

		public String getName() {
			return wrapped.getName();
		}

		public String getConfigProperty(String key) {
			return wrapped.getConfigProperty(key);
		}

		public boolean isLegacyProvider() {
			return true;
		}

		public String getHSNameFormatId() {
			return wrapped.getHSNameFormatId();
		}

		public IdentityProvider getIdentityProvider() {
			return wrapped.getIdentityProvider();
		}

		public String getProviderId() {
			return wrapped.getProviderId();
		}
	}
}
