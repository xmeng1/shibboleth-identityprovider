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

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugInException;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttribute;

/**
 * Wrapper class for custom <code>AttributeDefinitionPlugIn</code> implementations.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public class CustomAttributeDefinition implements ResolutionPlugIn, AttributeDefinitionPlugIn {

	private static Logger log = Logger.getLogger(CustomAttributeDefinition.class.getName());
	private AttributeDefinitionPlugIn custom;
	private String namespace = BaseAttributeDefinition.SHIB_ATTRIBUTE_NAMESPACE_URI;

	/** The time, in seconds, for which attribute created from this definition should be valid. */
	protected long lifeTime = -1;

	public CustomAttributeDefinition(Element e) throws ResolutionPlugInException {

		if (!e.getTagName().equals("CustomAttributeDefinition")) {
			log.error("Incorrect attribute definition configuration: expected <CustomAttributeDefinition> .");
			throw new ResolutionPlugInException("Failed to initialize Attribute Definition PlugIn.");
		}

		String className = e.getAttribute("class");
		if (className == null || className.equals("")) {
			log.error("Custom Attribute Definition requires specification of the attribute \"class\".");
			throw new ResolutionPlugInException("Failed to initialize Attribute Definition PlugIn.");
		} else {
			try {
				Class[] params = {Class.forName("org.w3c.dom.Element"),};
				Object[] passElement = {e};
				custom = (AttributeDefinitionPlugIn) Class.forName(className).getConstructor(params).newInstance(
						passElement);
			} catch (Exception loaderException) {
				log.error("Failed to load Custom Attribute Definition PlugIn implementation class: "
						+ loaderException.getMessage());
				throw new ResolutionPlugInException("Failed to initialize Attribute Definition PlugIn.");
			}
		}

		String lifeTimeSpec = e.getAttribute("lifeTime");
		if (lifeTimeSpec != null && !lifeTimeSpec.equals("")) {
			try {
				lifeTime = Long.valueOf(lifeTimeSpec).longValue();
				log.debug("Explicit lifetime set for attribute (" + getId() + ").  Lifetime: (" + lifeTime + ").");
			} catch (NumberFormatException nfe) {
				log.error("Bad value for attribute (lifeTime) for Attribute Definition (" + getId() + ").");
			}
		}

		String namespaceSpec = e.getAttribute("namespace");
		if (namespaceSpec != null && !namespaceSpec.equals("")) {
			namespace = namespaceSpec;
		}
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn#resolve(edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttribute,
	 *      java.security.Principal, java.lang.String, java.lang.String,
	 *      edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies)
	 */
	public void resolve(ResolverAttribute attribute, Principal principal, String requester, String responder,
			Dependencies depends) throws ResolutionPlugInException {

		custom.resolve(attribute, principal, requester, responder, depends);
		if (lifeTime != -1) {
			attribute.setLifetime(lifeTime);
		}
		attribute.setNamespace(namespace);
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
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn#getAttributeDefinitionDependencyIds()
	 */
	public String[] getAttributeDefinitionDependencyIds() {

		return custom.getAttributeDefinitionDependencyIds();
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn#getDataConnectorDependencyIds()
	 */
	public String[] getDataConnectorDependencyIds() {

		return custom.getDataConnectorDependencyIds();
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugIn#getPropagateErrors()
	 */
	public boolean getPropagateErrors() {

		return custom.getPropagateErrors();
	}
}