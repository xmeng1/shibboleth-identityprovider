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

package edu.internet2.middleware.shibboleth.idp.provider;

import java.util.HashSet;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.common.provider.ShibbolethTrust;
import edu.internet2.middleware.shibboleth.idp.IdPConfig;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolHandler;

/**
 * Functionality common to all <code>IdPProtocolHandler</code> implementation.
 * 
 * @author Walter Hoehn
 */
public abstract class BaseHandler implements IdPProtocolHandler {

	private static Logger log = Logger.getLogger(BaseHandler.class.getName());
	private HashSet locations = new HashSet();

	/**
	 * Required DOM-based constructor.
	 */
	public BaseHandler(Element config) throws ShibbolethConfigurationException {

		// Make sure we have at least one location
		NodeList locations = config.getElementsByTagNameNS(IdPConfig.configNameSpace, "Location");
		if (locations.getLength() < 1) {
			log.error("The <ProtocolHandler/> element must contain at least one <Location/> element.");
			throw new ShibbolethConfigurationException("Unable to load ProtocolHandler.");
		}

		// Parse the locations
		for (int i = 0; i < locations.getLength(); i++) {
			Node tnode = ((Element) locations.item(i)).getFirstChild();
			if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
				String rawURI = tnode.getNodeValue();

				if (rawURI == null || rawURI.equals("")) {
					log.error("The <Location/> element inside the <ProtocolHandler/> element must "
							+ "contain a URI or regular expressions.");
					throw new ShibbolethConfigurationException("Unable to load ProtocolHandler.");
				}
				this.locations.add(rawURI);

			} else {
				log.error("The <Location/> element inside the <ProtocolHandler/> element must contain a "
						+ "URI or regular expression.");
				throw new ShibbolethConfigurationException("Unable to load ProtocolHandler.");
			}
		}
	}

	/*
	 * @see edu.internet2.middleware.shibboleth.idp.IdPProtocolHandler#getLocations()
	 */
	public String[] getLocations() {

		return (String[]) locations.toArray(new String[0]);
	}

	protected static String getHostNameFromDN(X500Principal dn) {

		return ShibbolethTrust.getHostNameFromDN(dn);
	}

}