/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.] Licensed under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in
 * writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.aa.attrresolv.provider;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Iterator;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;

import org.apache.log4j.Logger;
import org.w3c.dom.CharacterData;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver;
import edu.internet2.middleware.shibboleth.aa.attrresolv.DataConnectorPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugInException;

/**
 * <code>DataConnectorPlugIn</code> implementation that allows static values to be declared in the resolver
 * configuration.
 * 
 * @author Walter Hoehn
 */
public class StaticDataConnector extends BaseResolutionPlugIn implements DataConnectorPlugIn {

	private static Logger log = Logger.getLogger(StaticDataConnector.class.getName());
	private ArrayList<Attribute> sourceData = new ArrayList<Attribute>();

	public StaticDataConnector(Element e) throws ResolutionPlugInException {

		super(e);

		NodeList attributeNodes = e.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "Attribute");
		if (attributeNodes.getLength() < 1) {
			log.error("Static Data Connector requires an \"Attribute\" specification.");
			throw new ResolutionPlugInException("Static Data Connector requires an \"Attribute\" specification.");
		}

		// Iterator over all <Attribute/> nodes
		// For each one, create a JNDI attribute object
		for (int i = 0; i < attributeNodes.getLength(); i++) {
			Element attributeElement = (Element) attributeNodes.item(i);
			String name = attributeElement.getAttribute("name");
			if (name == null) {
				log.error("Static Data Connector \"Attribute\" element requires a \"name\" specification.");
				throw new ResolutionPlugInException(
						"Static Data Connector \"Attribute\" element requires a \"name\" specification.");
			}

			// For each <Attribute/> element, iterator over all <Value/> children, pull the text node children and stick
			// them into the JNDI attribute as values
			Attribute attribute = new BasicAttribute(name, true);
			NodeList valueNodes = attributeElement.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "Value");
			if (valueNodes.getLength() < 1) {
				log.error("Static Data Connector \"Attribute\" element requires a \"Value\" element specification.");
				throw new ResolutionPlugInException(
						"Static Data Connector \"Attribute\" element requires a \"Value\" element specification.");
			}

			for (int j = 0; j < valueNodes.getLength(); j++) {
				Element valueElement = (Element) valueNodes.item(j);
				if (!valueElement.hasChildNodes() || valueElement.getFirstChild().getNodeType() != Node.TEXT_NODE) {
					log.error("Static Data Connector \"Value\" specification must contain text data.");
					throw new ResolutionPlugInException(
							"Static Data Connector \"Value\" specification must contain text data.");
				}
				attribute.add(((CharacterData) valueElement.getFirstChild()).getData());

			}
			sourceData.add(attribute);
		}
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.DataConnectorPlugIn#resolve(java.security.Principal,
	 *      java.lang.String, java.lang.String, edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies)
	 */
	public Attributes resolve(Principal principal, String requester, String responder, Dependencies depends)
			throws ResolutionPlugInException {

		log.debug("Resolving connector: (" + getId() + ")");
		log.debug(getId() + " resolving for principal: (" + principal.getName() + ")");

		BasicAttributes attributes = new BasicAttributes();
		Iterator<Attribute> iterator = sourceData.iterator();
		while (iterator.hasNext()) {
			Attribute attribute = (Attribute) iterator.next().clone();
			for (int i = 0; i < attribute.size(); i++) {
				try {
					attribute.set(i, ((String) attribute.get(i)).replaceAll("%PRINCIPAL%", principal.getName()));
				} catch (NamingException e) {
					log.error("Error constructing static attribute values: " + e);
					throw new ResolutionPlugInException("Error constructing static attribute values.");
				}
			}
			attributes.put(attribute);
		}

		return attributes;
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.DataConnectorPlugIn#getFailoverDependencyId()
	 */
	public String getFailoverDependencyId() {

		return null;
	}
}
