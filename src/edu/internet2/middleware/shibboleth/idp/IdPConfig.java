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

package edu.internet2.middleware.shibboleth.idp;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;

/**
 * @author Walter Hoehn
 */
public class IdPConfig {

	// TODO re-evaluate whether or not we need this class... most of it has gone away anyway

	public static final String configNameSpace = "urn:mace:shibboleth:idp:config:1.0";
	private String resolverConfig = "/conf/resolver.xml";

	private int maxThreads = 30;

	private static Logger log = Logger.getLogger(IdPConfig.class.getName());

	public IdPConfig(Element config) throws ShibbolethConfigurationException {

		if (!config.getTagName().equals("IdPConfig")) { throw new ShibbolethConfigurationException(
				"Unexpected configuration data.  <IdPConfig/> is needed."); }

		log.debug("Loading global configuration properties.");

		// Attribute resolver config file location
		String rawResolverConfig = ((Element) config).getAttribute("resolverConfig");
		if (rawResolverConfig != null && !rawResolverConfig.equals("")) {
			resolverConfig = rawResolverConfig;
		}

		String attribute = ((Element) config).getAttribute("maxSigningThreads");
		if (attribute != null && !attribute.equals("")) {
			try {
				maxThreads = Integer.parseInt(attribute);
			} catch (NumberFormatException e) {
				log.error("(maxSigningThreads) attribute to is not a valid integer.");
				throw new ShibbolethConfigurationException("Configuration is invalid.");
			}
		}

		attribute = ((Element) config).getAttribute("authHeaderName");

		log.debug("Global IdP config: (maxSigningThreads) = (" + getMaxThreads() + ").");

		log.debug("Global IdP config: (resolverConfig) = (" + getResolverConfigLocation() + ").");

	}

	public String getResolverConfigLocation() {

		return resolverConfig;
	}

	public int getMaxThreads() {

		return maxThreads;
	}

}