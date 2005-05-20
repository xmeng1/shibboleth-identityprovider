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

import java.util.LinkedHashSet;
import java.util.Set;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugInException;

/**
 * Base class for Resolution PlugIns, both <code>AttributeDefinitionPlugIn</code>&<code>DataConnectorPlugIn</code>
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */

public abstract class BaseResolutionPlugIn implements ResolutionPlugIn {

	private static Logger log = Logger.getLogger(BaseResolutionPlugIn.class.getName());

	/** The identifier for this PlugIn. */
	protected String id;

	/** Time, in seconds, for which the Attribute Resolver should cache resolutions of this PlugIn. */
	protected long ttl = 0;

	/** Whether to propagate errors out of the PlugIn as exceptions. */
	protected boolean propagateErrors = true;

	/** Dependencies. */
	protected Set connectorDependencyIds = new LinkedHashSet();
	protected Set attributeDependencyIds = new LinkedHashSet();

	protected BaseResolutionPlugIn(Element e) throws ResolutionPlugInException {

		String id = e.getAttribute("id");
		if (id == null || id.equals("")) {
			log.error("Attribute \"id\" required to configure plugin.");
			throw new ResolutionPlugInException("Failed to initialize Resolution PlugIn.");
		}
		this.id = id;

		String cacheTime = e.getAttribute("cacheTime");
		if (cacheTime != null && !cacheTime.equals("")) {
			try {
				this.ttl = Long.parseLong(cacheTime);
			} catch (NumberFormatException nfe) {
				log.error("Attribute \"cacheTime\" must be an integer between 0 and " + Long.MAX_VALUE + ".");
				throw new ResolutionPlugInException("Failed to initialize Resolution PlugIn.");
			}
		}

		String propagateFlag = e.getAttribute("propagateErrors");
		if (propagateFlag != null && (propagateFlag.equals("false") || propagateFlag.equals("0"))) {
			propagateErrors = false;
		}

		NodeList connectorNodes = e.getElementsByTagNameNS(AttributeResolver.resolverNamespace,
				"DataConnectorDependency");

		for (int i = 0; connectorNodes.getLength() > i; i++) {
			Element connector = (Element) connectorNodes.item(i);
			String connectorName = connector.getAttribute("requires");
			if (connectorName != null && !connectorName.equals("")) {
				addDataConnectorDependencyId(connectorName);
			} else {
				log.error("Data Connector dependency must be accompanied by a \"requires\" attribute.");
				throw new ResolutionPlugInException("Failed to initialize Resolution PlugIn.");
			}
		}

		NodeList attributeNodes = e.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "AttributeDependency");
		for (int i = 0; attributeNodes.getLength() > i; i++) {
			Element attribute = (Element) attributeNodes.item(i);
			String attributeName = attribute.getAttribute("requires");
			if (attributeName != null && !attributeName.equals("")) {
				addAttributeDefinitionDependencyId(attributeName);
			} else {
				log.error("Attribute Definition dependency must be accompanied by a \"requires\" attribute.");
				throw new ResolutionPlugInException("Failed to initialize Resolution PlugIn.");
			}
		}
	}

	/** Returns the identifier for this PlugIn. */
	public String getId() {

		return id;
	}

	/** Returns the time, in seconds, for which the Attribute Resolver should cache resolutions of this PlugIn. */
	public long getTTL() {

		return ttl;
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugIn#getPropagateErrors()
	 */
	public boolean getPropagateErrors() {

		return propagateErrors;
	}

	protected void addDataConnectorDependencyId(String id) {

		connectorDependencyIds.add(id);
	}

	protected void addAttributeDefinitionDependencyId(String id) {

		attributeDependencyIds.add(id);
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugIn#getAttributeDependencyIds()
	 */
	public String[] getAttributeDefinitionDependencyIds() {

		return (String[]) attributeDependencyIds.toArray(new String[0]);
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugIn#getConnectorDependencyIds()
	 */
	public String[] getDataConnectorDependencyIds() {

		return (String[]) connectorDependencyIds.toArray(new String[0]);
	}
}
