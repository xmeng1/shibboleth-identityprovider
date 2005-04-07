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

package edu.internet2.middleware.shibboleth.idp;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;

/**
 * @author Walter Hoehn
 */
public class IdPConfig {

	private String defaultRelyingPartyName;
	private String providerId;
	public static final String configNameSpace = "urn:mace:shibboleth:idp:config:1.0";
	private String resolverConfig = "/conf/resolver.xml";
	private boolean passThruErrors = false;
	private int maxThreads = 5;
	private String authHeaderName = "REMOTE_USER";
	private URI defaultAuthMethod;
	private URL AAUrl;

	private static Logger log = Logger.getLogger(IdPConfig.class.getName());

	public IdPConfig(Element config) throws ShibbolethConfigurationException {

		if (!config.getTagName().equals("IdPConfig") && !config.getTagName().equals("ShibbolethOriginConfig")) { throw new ShibbolethConfigurationException(
				"Unexpected configuration data.  <IdPConfig/> is needed."); }

		log.debug("Loading global configuration properties.");

		// Global providerId
		providerId = ((Element) config).getAttribute("providerId");
		if (providerId == null || providerId.equals("")) {
			log.error("Global providerId not set.  Add a (providerId) attribute to <IdPConfig/>.");
			throw new ShibbolethConfigurationException("Required configuration not specified.");
		}

		// Default Relying Party
		defaultRelyingPartyName = ((Element) config).getAttribute("defaultRelyingParty");
		if (defaultRelyingPartyName == null || defaultRelyingPartyName.equals("")) {
			log.error("Default Relying Party not set.  Add a (defaultRelyingParty) attribute to <IdPConfig/>.");
			throw new ShibbolethConfigurationException("Required configuration not specified.");
		}

		// Attribute resolver config file location
		String rawResolverConfig = ((Element) config).getAttribute("resolverConfig");
		if (rawResolverConfig != null && !rawResolverConfig.equals("")) {
			resolverConfig = rawResolverConfig;
		}

		// Global Pass thru error setting
		String attribute = ((Element) config).getAttribute("passThruErrors");
		if (attribute != null && !attribute.equals("")) {
			passThruErrors = Boolean.valueOf(attribute).booleanValue();
		}

		attribute = ((Element) config).getAttribute("AAUrl");
		if (attribute == null || attribute.equals("")) {
			log.error("Global Attribute Authority URL not set.  Add an (AAUrl) attribute to <IdPConfig/>.");
			throw new ShibbolethConfigurationException("Required configuration not specified.");
		}
		try {
			AAUrl = new URL(attribute);
		} catch (MalformedURLException e) {
			log.error("(AAUrl) attribute to is not a valid URL.");
			throw new ShibbolethConfigurationException("Required configuration is invalid.");
		}

		attribute = ((Element) config).getAttribute("defaultAuthMethod");
		if (attribute == null || attribute.equals("")) {
			try {
				defaultAuthMethod = new URI("urn:oasis:names:tc:SAML:1.0:am:unspecified");
			} catch (URISyntaxException e1) {
				// Shouldn't happen
				throw new ShibbolethConfigurationException("Default Auth Method URI could not be constructed.");
			}
		} else {
			try {
				defaultAuthMethod = new URI(attribute);
			} catch (URISyntaxException e1) {
				log.error("(defaultAuthMethod) attribute to is not a valid URI.");
				throw new ShibbolethConfigurationException("Required configuration is invalid.");
			}
		}

		attribute = ((Element) config).getAttribute("maxHSThreads");
		if (attribute != null && !attribute.equals("")) {
			try {
				maxThreads = Integer.parseInt(attribute);
			} catch (NumberFormatException e) {
				log.error("(maxHSThreads) attribute to is not a valid integer.");
				throw new ShibbolethConfigurationException("Configuration is invalid.");
			}
		}

		attribute = ((Element) config).getAttribute("authHeaderName");
		if (attribute != null && !attribute.equals("")) {
			authHeaderName = attribute;
		}

		log.debug("Global IdP config: (AAUrl) = (" + getAAUrl() + ").");
		log.debug("Global IdP config: (defaultAuthMethod) = (" + getDefaultAuthMethod() + ").");
		log.debug("Global IdP config: (maxHSThreads) = (" + getMaxThreads() + ").");
		log.debug("Global IdP config: (authHeaderName) = (" + getAuthHeaderName() + ").");

		log.debug("Global IdP config: (resolverConfig) = (" + getResolverConfigLocation() + ").");
		log.debug("Global IdP config: (passThruErrors) = (" + passThruErrors() + ").");
		log.debug("Global IdP config: Default Relying Party: (" + getDefaultRelyingPartyName() + ").");
	}

	public String getProviderId() {

		return providerId;
	}

	public String getDefaultRelyingPartyName() {

		return defaultRelyingPartyName;
	}

	public String getResolverConfigLocation() {

		return resolverConfig;
	}

	public boolean passThruErrors() {

		return passThruErrors;
	}

	public int getMaxThreads() {

		return maxThreads;
	}

	public String getAuthHeaderName() {

		return authHeaderName;
	}

	public URI getDefaultAuthMethod() {

		return defaultAuthMethod;
	}

	public URL getAAUrl() {

		return AAUrl;
	}
}
