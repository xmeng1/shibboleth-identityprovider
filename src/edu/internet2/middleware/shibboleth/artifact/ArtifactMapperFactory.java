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

package edu.internet2.middleware.shibboleth.artifact;

import java.lang.reflect.Constructor;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;

/**
 * Factory for generating instances of <code>ArtifactMapper</code>. Configuration is delegated to the implementation.
 * Runtime options are passed to concrete constructors via an <ArtifactMapper/>DOM element.
 * 
 * @author Walter Hoehn
 */
public class ArtifactMapperFactory {

	private static Logger log = Logger.getLogger(ArtifactMapperFactory.class.getName());

	public static ArtifactMapper getInstance(Element config) throws ShibbolethConfigurationException {

		if (config.getAttribute("implementation") == null) { throw new ShibbolethConfigurationException(
				"No ArtifactMapper implementaiton specified."); }
		try {
			Class implementorClass = Class.forName(config.getAttribute("implementation"));
			Class[] params = new Class[1];
			params[0] = Class.forName("org.w3c.dom.Element");
			Constructor implementorConstructor = implementorClass.getConstructor(params);
			Object[] args = new Object[1];
			args[0] = config;
			log.debug("Initializing Artifact Mapper of type (" + implementorClass.getName() + ").");
			return (ArtifactMapper) implementorConstructor.newInstance(args);

		} catch (NoSuchMethodException nsme) {
			log.error("Failed to instantiate an Artifact Mapper: ArtifactMapper "
					+ "implementation must contain a constructor that accepts an <ArtifactMapper/> element as "
					+ "configuration data.");
			throw new ShibbolethConfigurationException("Failed to instantiate an Artifact Mapper.");

		} catch (Exception e) {
			log.error("Failed to instantiate an Artifact Mapper: " + e);
			throw new ShibbolethConfigurationException("Failed to instantiate an Artifact Mapper: " + e.getMessage());

		}
	}
}
