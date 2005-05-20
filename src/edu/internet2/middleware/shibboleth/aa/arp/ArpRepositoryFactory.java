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

package edu.internet2.middleware.shibboleth.aa.arp;

import java.lang.reflect.Constructor;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

/**
 * Factory for generating instances of <code>ArpRepository</code>. Configuration is delegated to the Arp Repository.
 * Runtime options are passed to concrete constructors via an <ArpRepository/>element.
 * 
 * @author Parviz Dousti (dousti@cmu.edu)
 * @created June, 2002
 */

public class ArpRepositoryFactory {

	private static Logger log = Logger.getLogger(ArpRepositoryFactory.class.getName());

	public static ArpRepository getInstance(Element repositoryConfig) throws ArpRepositoryException {

		if (repositoryConfig.getAttribute("implementation") == null) { throw new ArpRepositoryException(
				"No ARP Repository implementaiton specified."); }
		try {
			Class implementorClass = Class.forName(repositoryConfig.getAttribute("implementation"));
			Class[] params = new Class[1];
			params[0] = Class.forName("org.w3c.dom.Element");
			Constructor implementorConstructor = implementorClass.getConstructor(params);
			Object[] args = new Object[1];
			args[0] = repositoryConfig;
			log.debug("Initializing Arp Repository of type (" + implementorClass.getName() + ").");
			return (ArpRepository) implementorConstructor.newInstance(args);

		} catch (NoSuchMethodException nsme) {
			log.error("Failed to instantiate an Arp Repository: ArpRepository "
					+ "implementation must contain a constructor that accepts an <ArpRepository> element as "
					+ "configuration data.");
			throw new ArpRepositoryException("Failed to instantiate an Arp Repository.");
		} catch (Exception e) {
			log.error("Failed to instantiate an Arp Repository: " + e);
			throw new ArpRepositoryException("Failed to instantiate an Arp Repository: " + e.getMessage());

		}
	}
}
