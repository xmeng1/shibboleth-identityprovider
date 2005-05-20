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

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver;
import edu.internet2.middleware.shibboleth.aa.attrresolv.DataConnectorPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugInException;

/**
 * Base class for Data Connector PlugIns. Provides basic functionality such as failover tracking. Subclasses must
 * provide resolution logic.
 * 
 * @author Scott Cantor (cantor.2@osu.edu)
 */

public abstract class BaseDataConnector extends BaseResolutionPlugIn implements DataConnectorPlugIn {

	/** A backup connector to use if this one fails. */
	protected String failover = null;

	protected BaseDataConnector(Element e) throws ResolutionPlugInException {

		super(e);

		NodeList failoverNodes = e.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "FailoverDependency");
		if (failoverNodes.getLength() > 0) {
			failover = ((Element) failoverNodes.item(0)).getAttribute("requires");
		}
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.DataConnectorPlugIn#getFailoverDependencyId()
	 */
	public String getFailoverDependencyId() {

		return failover;
	}

}
