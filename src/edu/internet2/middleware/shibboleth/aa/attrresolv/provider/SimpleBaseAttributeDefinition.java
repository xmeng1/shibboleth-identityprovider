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

/*
 * Contributed by SunGard SCT.
 */

package edu.internet2.middleware.shibboleth.aa.attrresolv.provider;

import java.security.Principal;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugInException;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttribute;

/**
 * This is an abstract class that all other attribute definitions in this package extend. It provides processing of
 * common attributes as well as dependency resolutions.
 * 
 * @author <a href="mailto:vgoenka@sungardsct.com">Vishal Goenka </a>
 */
abstract class SimpleBaseAttributeDefinition extends BaseAttributeDefinition implements AttributeDefinitionPlugIn {

	private static Logger log = Logger.getLogger(SimpleBaseAttributeDefinition.class.getName());

	protected ValueHandler valueHandler;
	protected String connectorMapping;

	protected SimpleBaseAttributeDefinition(Element e) throws ResolutionPlugInException {

		super(e);

		String sourceName = e.getAttribute("sourceName");
		if (sourceName == null || sourceName.equals("")) {
			int index = getId().lastIndexOf("#");
			if (index < 0) {
				index = getId().lastIndexOf(":");
				int slashIndex = getId().lastIndexOf("/");
				if (slashIndex > index) {
					index = slashIndex;
				}
			}
			connectorMapping = getId().substring(index + 1);
		} else {
			connectorMapping = sourceName;
		}

		String valueHandlerSpec = e.getAttribute("valueHandler");

		if (valueHandlerSpec != null && !valueHandlerSpec.equals("")) {
			try {
				Class handlerClass = Class.forName(valueHandlerSpec);
				valueHandler = (ValueHandler) handlerClass.newInstance();
			} catch (ClassNotFoundException cnfe) {
				log.error("Value Handler implementation specified for attribute (" + getId() + ") cannot be found: "
						+ cnfe);
				throw new ResolutionPlugInException("Value Handler implementation specified for attribute (" + getId()
						+ ") cannot be found.");
			} catch (Exception oe) {
				log.error("Value Handler implementation specified for attribute (" + getId()
						+ ") coudl not be loaded: " + oe);
				throw new ResolutionPlugInException("Value Handler implementation specified for attribute (" + getId()
						+ ") could not be loaded.");
			}
		}

		if (valueHandler != null) {
			log.debug("Custom Value Handler enabled for attribute (" + getId() + ").");
		}

	}

	protected Collection resolveDependencies(ResolverAttribute attribute, Principal principal, String requester,
			Dependencies depends) throws ResolutionPlugInException {

		log.debug("Resolving attribute: (" + getId() + ")");

		Set results = new LinkedHashSet();
		if (!connectorDependencyIds.isEmpty()) {
			results.addAll(Arrays.asList(getValuesFromConnectors(depends)));
		}

		if (!attributeDependencyIds.isEmpty()) {
			results.addAll(Arrays.asList(getValuesFromAttributes(depends)));
		}

		if (valueHandler != null) {
			attribute.registerValueHandler(valueHandler);
		}

		return results;
	}

	protected Object[] getValuesFromAttributes(Dependencies depends) {

		Set results = new LinkedHashSet();

		Iterator attrDependIt = attributeDependencyIds.iterator();
		while (attrDependIt.hasNext()) {
			ResolverAttribute attribute = depends.getAttributeResolution((String) attrDependIt.next());
			if (attribute != null) {
				log.debug("Found value(s) for attribute (" + getId() + ").");
				for (Iterator iterator = attribute.getValues(); iterator.hasNext();) {
					results.add(iterator.next());
				}
			} else {
				log.error("An attribute dependency of attribute (" + getId()
						+ ") was not included in the dependency chain.");
			}
		}

		if (results.isEmpty()) {
			log.debug("An attribute dependency of attribute (" + getId() + ") supplied no values.");
		}
		return results.toArray();
	}

	protected Object[] getValuesFromConnectors(Dependencies depends) {

		Set results = new LinkedHashSet();

		Iterator connectorDependIt = connectorDependencyIds.iterator();
		while (connectorDependIt.hasNext()) {
			Attributes attrs = depends.getConnectorResolution((String) connectorDependIt.next());
			if (attrs != null) {
				Attribute attr = attrs.get(connectorMapping);
				if (attr != null) {
					log.debug("Found value(s) for attribute (" + getId() + ").");
					try {
						NamingEnumeration valuesEnum = attr.getAll();
						while (valuesEnum.hasMore()) {
							results.add(valuesEnum.next());
						}
					} catch (NamingException e) {
						log.error("An problem was encountered resolving the dependencies of attribute (" + getId()
								+ "): " + e);
					}
				}
			}
		}

		if (results.isEmpty()) {
			log.debug("A connector dependency of attribute (" + getId() + ") supplied no values.");
		}
		return results.toArray();
	}

	protected String getString(Object value) {

		// if (value instanceof String) return (String)value;
		// This was inspired by the fact that certain attributes (such as userPassword, when read using JNDI) are
		// returned
		// from data connectors as byte [] rather than String, and doing a .toString() returns something like
		// B[@aabljadj,
		// which is a reference to the array, rather than the string value.
		if (value instanceof byte[]) return new String((byte[]) value);
		return value.toString();
	}

}