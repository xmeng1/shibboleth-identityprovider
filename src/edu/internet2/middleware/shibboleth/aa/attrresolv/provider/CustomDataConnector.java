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

package edu.internet2.middleware.shibboleth.aa.attrresolv.provider;

import java.security.Principal;

import javax.naming.directory.Attributes;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.attrresolv.DataConnectorPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugInException;

/**
 * Wrapper class for custom <code>DataConnectorPlugIn</code> implementations.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public class CustomDataConnector implements DataConnectorPlugIn {

	private static Logger log = Logger.getLogger(CustomDataConnector.class.getName());
	private DataConnectorPlugIn custom;

	public CustomDataConnector(Element e) throws ResolutionPlugInException {

		if (!e.getTagName().equals("CustomDataConnector")) {
			log.error("Incorrect connector configuration: expected <CustomDataConnector> .");
			throw new ResolutionPlugInException("Failed to initialize Connector PlugIn.");
		}

		String className = e.getAttribute("class");
		if (className == null || className.equals("")) {
			log.error("Custom Data Connector requires specification of attributes \"class\".");
			throw new ResolutionPlugInException("Failed to initialize Connector PlugIn.");
		} else {
			try {
				Class[] params = {Class.forName("org.w3c.dom.Element"),};
				Object[] passElement = {e};
				custom = (DataConnectorPlugIn) Class.forName(className).getConstructor(params).newInstance(passElement);
			} catch (Exception loaderException) {
				// Try to be a little smart about logging errors
				// For some reason the message is not set on ClassNotFoundException
				log.error("Failed to load Custom Connector PlugIn implementation class: "
						+ ((loaderException.getCause() != null)
								? loaderException.getCause().getMessage()
								: loaderException.toString()));
				throw new ResolutionPlugInException("Failed to initialize Connector PlugIn.");
			}
		}
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.DataConnectorPlugIn#resolve(java.security.Principal,
	 *      java.lang.String, java.lang.String, edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies)
	 */
	public Attributes resolve(Principal principal, String requester, String responder, Dependencies depends)
			throws ResolutionPlugInException {

		return custom.resolve(principal, requester, responder, depends);
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.BaseResolutionPlugIn#getId()
	 */
	public String getId() {

		return custom.getId();
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.provider.BaseResolutionPlugIn#getTTL()
	 */
	public long getTTL() {

		return custom.getTTL();
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugIn#getAttributeDefinitionDependencyIds()
	 */
	public String[] getAttributeDefinitionDependencyIds() {

		return custom.getAttributeDefinitionDependencyIds();
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugIn#getDataConnectorDependencyIds()
	 */
	public String[] getDataConnectorDependencyIds() {

		return custom.getDataConnectorDependencyIds();
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.DataConnectorPlugIn#getFailoverDependencyId()
	 */
	public String getFailoverDependencyId() {

		return custom.getFailoverDependencyId();
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugIn#getPropagateErrors()
	 */
	public boolean getPropagateErrors() {

		return custom.getPropagateErrors();
	}
}
