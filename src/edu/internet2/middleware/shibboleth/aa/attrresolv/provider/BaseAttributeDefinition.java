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

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugInException;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttribute;

/**
 * Base class for Attribute Definition PlugIns. Provides basic functionality such as dependency mapping. Subclasses must
 * provide resolution logic.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */

public abstract class BaseAttributeDefinition extends BaseResolutionPlugIn implements AttributeDefinitionPlugIn {

	/** The time, in seconds, for which attribute created from this definition should be valid. */
	protected long lifeTime = -1;
	public final static String SHIB_ATTRIBUTE_NAMESPACE_URI = "urn:mace:shibboleth:1.0:attributeNamespace:uri";
	protected String namespace = SHIB_ATTRIBUTE_NAMESPACE_URI;

	private static Logger log = Logger.getLogger(BaseAttributeDefinition.class.getName());

	protected BaseAttributeDefinition(Element e) throws ResolutionPlugInException {

		super(e);

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
	 * Should be run by all sublcasses during resolution.
	 */
	protected void standardProcessing(ResolverAttribute attr) {

		if (lifeTime != -1) {
			attr.setLifetime(lifeTime);
		}

		attr.setNamespace(namespace);
	}
}