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
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.attrresolv.DataConnectorPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugInException;

/**
 * Sample <code>DataConnectorPlugIn</code> implementation. Echos principal name in EPPN.
 * 
 * @author Walter Hoehn
 */
public class SampleConnector extends BaseResolutionPlugIn implements DataConnectorPlugIn {

	private static Logger log = Logger.getLogger(SampleConnector.class.getName());

	public SampleConnector(Element e) throws ResolutionPlugInException {

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
		attributes.put(new BasicAttribute("eduPersonAffiliation", "member"));
		attributes.put(new BasicAttribute("eduPersonEntitlement", "urn:mace:example.edu:exampleEntitlement"));
		return attributes;
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.DataConnectorPlugIn#getFailoverDependencyId()
	 */
	public String getFailoverDependencyId() {

		return null;
	}
}
