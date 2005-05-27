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

import javax.servlet.ServletContext;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;

import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.xml.Parser;

/**
 * Constructs a DOM tree for the IdP configuration XML file.
 * 
 * @author Walter Hoehn
 * @author Noah Levitt
 */
public class IdPConfigLoader {

	private static Logger log = Logger.getLogger(IdPConfigLoader.class);
	private static Document idpConfig = null;
	private static String idpConfigFile = null;

	/**
	 * Returnes the location of the configuration file.
	 * 
	 * @param context
	 *            the context of the IdP servlet
	 * @return the location of the configuration file
	 */
	private static String getIdPConfigFile(ServletContext context) {

		if (context.getInitParameter("IdPConfigFile") != null) {
			return context.getInitParameter("IdPConfigFile");
		} else {
			return "/conf/idp.xml";
		}
	}

	/**
	 * Loads the IdP Configuration file into a DOM tree.
	 * 
	 * @param configFileLocation
	 *            URL of the configuration file
	 * @return the DOM Document
	 * @throws ShibbolethConfigurationException
	 *             if there was an error loading the file
	 */
	public static synchronized Document getIdPConfig(String configFileLocation) throws ShibbolethConfigurationException {

		if (log.isDebugEnabled()) {
			log.debug("Getting IdP configuration file: " + configFileLocation);
		}

		if (configFileLocation.equals(idpConfigFile)) {
			return idpConfig;

		} else if (idpConfigFile == null) {
			idpConfigFile = configFileLocation;

		} else {
			log.error("Previously read IdP configuration from (" + idpConfigFile + "), re-reading from ("
					+ configFileLocation + "). This probably indicates a bug in shibboleth.");
			idpConfigFile = configFileLocation;
		}

		try {
			idpConfig = Parser.loadDom(configFileLocation, true);

			if (idpConfig == null) { throw new Exception("IdP configuration could not be loaded from (" + idpConfigFile
					+ ")."); }

			if (log.isDebugEnabled()) {
				log.debug("IdP configuration file " + configFileLocation + " successfully read and cached.");
			}
		} catch (Exception e) {
			System.err.println("Unable to parse Shibboleth Identity Provider configuration file: " + e);
			throw new ShibbolethConfigurationException(
					"Encountered an error while parsing Shibboleth Identity Provider configuration file: " + e);
		}
		return idpConfig;
	}

	/**
	 * Loads the IdP Configuration file into a DOM tree.
	 * 
	 * @param context
	 *            {@link ServletContext}from which to figure out the location of IdP
	 * @return the DOM Document
	 * @throws ShibbolethConfigurationException
	 *             if there was an error loading the file
	 */
	public static Document getIdPConfig(ServletContext context) throws ShibbolethConfigurationException {

		return getIdPConfig(getIdPConfigFile(context));

	}
}
