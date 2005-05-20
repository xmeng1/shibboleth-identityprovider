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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;

/**
 * Factory class for loading <code>ProtocolHandler</code> implementations based on xml configuration.
 * 
 * @author Walter Hoehn
 */
public class ProtocolHandlerFactory {

	private static Logger log = Logger.getLogger(ProtocolHandlerFactory.class.getName());

	public static IdPProtocolHandler getInstance(Element config) throws ShibbolethConfigurationException {

		String implementation = config.getAttribute("implementation");
		if (implementation == null || implementation.equals("")) {
			log.error("No Protocol Handler implementation specified.  Attribute (implementation) is "
					+ "required with element <ProtocolHandler/>.");
			throw new ShibbolethConfigurationException("Invalid configuration data supplied.");

		} else {

			try {
				log.debug("Loading Protocol Handler implementation: (" + implementation + ").");
				Class implClass = Class.forName(implementation);
				Constructor constructor = implClass.getConstructor(new Class[]{Element.class});
				Object rawImpl = constructor.newInstance(new Object[]{config});

				if (rawImpl instanceof IdPProtocolHandler) {
					return (IdPProtocolHandler) rawImpl;
				} else {
					log.error("Invalid configuration, supplied implementation class for the Protocol Handler "
							+ "does not properly implement the required IdPProtocolHandler interface.");
					throw new ShibbolethConfigurationException("Invalid configuration data supplied.");
				}

			} catch (ClassNotFoundException e) {
				log.error("Invalid configuration, supplied implementation class for the Protocol Handler "
						+ "could not be found: " + e.getMessage());
				throw new ShibbolethConfigurationException("Invalid configuration data supplied.");

			} catch (NoSuchMethodException e) {
				log.error("Invalid configuration, supplied implementation class for the Protocol Handler is "
						+ "not valid.  A DOM Element constructor is required: " + e.getMessage());
				throw new ShibbolethConfigurationException("Invalid configuration data supplied.");

			} catch (InvocationTargetException e) {
				Throwable cause = e.getCause();
				if (cause != null) {
					log.error(cause.getMessage());
				}
				log.error("Invalid configuration, supplied implementation class for the Protocol Handler"
						+ " could not be loaded: " + e.getMessage());
				throw new ShibbolethConfigurationException("Invalid configuration data supplied.");
			} catch (Exception e) {
				log.error("Invalid configuration, supplied implementation class for the Protocol Handler"
						+ " could not be loaded: " + e.getMessage());
				throw new ShibbolethConfigurationException("Invalid configuration data supplied.");
			}
		}
	}

}