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

package edu.internet2.middleware.shibboleth.aa.attrresolv;

import java.security.Principal;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.BaseDataConnector;

/**
 * <code>DataConnectorPlugIn</code> implementation for use in unit testing.
 * 
 * @author Walter Hoehn
 */
public class ScopeTestConnector extends BaseDataConnector implements DataConnectorPlugIn {

	private static Logger log = Logger.getLogger(ScopeTestConnector.class.getName());

	public ScopeTestConnector(Element e) throws ResolutionPlugInException {

		super(e);
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.DataConnectorPlugIn#resolve(java.security.Principal,
	 *      java.lang.String, java.lang.String, edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies)
	 */
	public Attributes resolve(Principal principal, String requester, String responder, Dependencies depends) {

		log.debug("Resolving connector: (" + getId() + ")");
		log.debug(getId() + " resolving for principal: (" + principal.getName() + ")");

		BasicAttributes attributes = new BasicAttributes();
		attributes.put(new BasicAttribute("eduPersonPrincipalName", principal.getName()));
		attributes.put(new BasicAttribute("foo", "bar@example.com"));
		return attributes;
	}
}
