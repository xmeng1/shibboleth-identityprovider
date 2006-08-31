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
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugInException;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttribute;

/**
 * Basic <code>AttributeDefinitionPlugIn</code> implementation. Operates as a proxy for attributes gathered by
 * Connectors.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public class SimpleAttributeDefinition extends BaseAttributeDefinition implements AttributeDefinitionPlugIn {

	private static Logger log = Logger.getLogger(SimpleAttributeDefinition.class.getName());
	private String smartScope;
	private boolean allowEmpty = false;
	private boolean downCase = false;

	/**
	 * Constructor for SimpleAttributeDefinition. Creates a PlugIn based on configuration information presented in a DOM
	 * Element.
	 */
	public SimpleAttributeDefinition(Element e) throws ResolutionPlugInException {

		super(e);

		// Configure smart scoping
		String smartScopingSpec = e.getAttribute("smartScope");
		if (smartScopingSpec != null && !smartScopingSpec.equals("")) {
			smartScope = smartScopingSpec;
		}
		if (smartScope != null) {
			log.debug("Smart Scope (" + smartScope + ") enabled for attribute (" + getId() + ").");
		} else {
			log.debug("Smart Scoping disabled for attribute (" + getId() + ").");
		}

		if (smartScope != null && valueHandler != null) {
			log.error("Specification of \"valueHandler\' cannot be used in combination with \"smartScope\". "
					+ " Ignoring Value Handler for attribute (" + getId() + ").");
		}

		// Decide whether or not to allow empty string values
		String rawAllowEmpty = e.getAttribute("allowEmpty");
		if (rawAllowEmpty != null) {
			if (rawAllowEmpty.equalsIgnoreCase("TRUE")) {
				allowEmpty = true;
			}
		}

		log.debug("Allowal of empty string values is set to (" + allowEmpty + ") for attribute (" + getId() + ").");

		// Decide whether or not to force values to lower case
		String rawDownCase = e.getAttribute("downCase");
		if (rawDownCase != null) {
			if (rawDownCase.equalsIgnoreCase("TRUE")) {
				downCase = true;
				log.debug("Forcing values to lower case for attribute (" + getId() + ").");
			}
		}

	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn#resolve(edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttribute,
	 *      java.security.Principal, java.lang.String, java.lang.String,
	 *      edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies)
	 */
	public void resolve(ResolverAttribute attribute, Principal principal, String requester, String responder,
			Dependencies depends) throws ResolutionPlugInException {

		super.resolve(attribute, principal, requester, responder, depends);

		log.debug("Resolving attribute: (" + getId() + ")");
		Set<Object> results = new LinkedHashSet<Object>();
		if (!connectorDependencyIds.isEmpty()) {
			results.addAll(getAllValuesFromConnectorDeps(depends));
		}

		if (!attributeDependencyIds.isEmpty()) {
			results.addAll(getAllValuesFromAttributeDeps(depends));
		}

		if (smartScope != null) {
			attribute.registerValueHandler(new ScopedStringValueHandler(smartScope));
		}

		Iterator resultsIt = results.iterator();
		while (resultsIt.hasNext()) {
			Object value = resultsIt.next();
			if (!allowEmpty && ((value == null || value.equals("")))) {
				log.debug("Skipping empty string value.");
				continue;
			}

			if (downCase && value instanceof String) {
				value = ((String) value).toLowerCase();
			}

			attribute.addValue(value);
		}
		attribute.setResolved();
	}
}
