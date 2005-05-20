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
 * Contributed by SungGard SCT.
 */

package edu.internet2.middleware.shibboleth.aa.attrresolv;

import java.security.Principal;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.BaseResolutionPlugIn;

/**
 * The FileConnector essentially returns the same attribute values for all principals/requestors. The returned
 * attributes are specified in a file as name-value pairs separated by an 'equals' sign (=). The datafile is specified
 * as an attribute on the definition of the FileConnector. Only one attribute, namely the eduPersonPrincipalName may
 * take different values for different principals. If this attribute is not specified in the properties file (datafile),
 * the principal name passed to the resolver is returned as EPPN. Multiple values of an attribute may be specified using
 * multiple pairs with the same attribute name. Multi-valued attributes are not considered ordered by default (to
 * emulate LDAP data connector) unless the attribute 'ordered' is set to true.
 * 
 * @author <a href="mailto:vgoenka@sungardsct.com">Vishal Goenka </a>
 */

public class FileConnector extends BaseResolutionPlugIn implements DataConnectorPlugIn {

	private static Logger log = Logger.getLogger(FileConnector.class.getName());
	private Attributes attributes;

	public FileConnector(Element e) throws ResolutionPlugInException {

		super(e);
		if (!e.hasAttribute("datafile"))
			throw new ResolutionPlugInException("datafile MUST be specified for FileConnector");
		String datafile = e.getAttribute("datafile");
		boolean ordered = false;
		if (e.hasAttribute("ordered")) ordered = Boolean.valueOf(e.getAttribute("ordered")).booleanValue();

		try {
			attributes = (new AttributesFile(datafile)).readAttributes(ordered);
		} catch (Exception ex) {
			log.error("Failed to read datafile <" + datafile + "> - " + ex.getMessage(), ex);
			throw new ResolutionPlugInException(ex.getMessage());
		}
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.DataConnectorPlugIn#resolve(Principal)
	 */
	public Attributes resolve(Principal principal, String requester, String responder, Dependencies depends) {

		log.debug("Resolving connector: (" + getId() + ")");
		log.debug(getId() + " resolving for principal: (" + principal.getName() + ")");

		BasicAttributes attrs = (BasicAttributes) attributes.clone();
		BasicAttribute eppn = (BasicAttribute) attrs.get("eduPersonPrincipalName");
		if (eppn == null) {
			attrs.put(new BasicAttribute("eduPersonPrincipalName", principal.getName()));
		}
		return attrs;
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.DataConnectorPlugIn#getFailoverDependencyId()
	 */
	public String getFailoverDependencyId() {

		return null;
	}
}