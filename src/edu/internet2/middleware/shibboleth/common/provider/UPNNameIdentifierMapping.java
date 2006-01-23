/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.] Licensed under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in
 * writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.common.provider;

import java.security.Principal;

import org.apache.log4j.Logger;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.IdentityProvider;
import edu.internet2.middleware.shibboleth.common.InvalidNameIdentifierException;
import edu.internet2.middleware.shibboleth.common.LocalPrincipal;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMappingException;
import edu.internet2.middleware.shibboleth.common.ServiceProvider;

/**
 * <code>NameIdentifierMapping</code> implementation for sending User Principal Names as referenced in "WS-Federation:
 * Passive Requestor Interoperability Profile". Should allow for basic interoperability with ADFS. IdPs that service
 * multiple account domains will need a slightly more complex implementation.
 * 
 * @author Walter Hoehn
 */
public class UPNNameIdentifierMapping extends BaseNameIdentifierMapping {

	private static Logger log = Logger.getLogger(UPNNameIdentifierMapping.class.getName());
	private String scope;

	public UPNNameIdentifierMapping(Element config) throws NameIdentifierMappingException {

		super(config);

		scope = config.getAttribute("scope");
		if (scope == null || scope.equals("")) {
			log.error("No (scope) attribute specified.");
			throw new NameIdentifierMappingException(
					"Unable to load UPN Name Identifier Mapping.  A UPN scope must be specified.");
		}
	}

	public Principal getPrincipal(SAMLNameIdentifier nameId, ServiceProvider sProv, IdentityProvider idProv)
			throws NameIdentifierMappingException, InvalidNameIdentifierException {

		String[] splitName = nameId.getName().split("@");

		if (splitName == null || splitName.length < 2) {
			log.error("Improper UPN formatting.  Unable to distinguish local principal from scope.");
			throw new InvalidNameIdentifierException("Name Identifier does not contain a valid UPN.", null);
		}
		if (splitName[1] == null || (!splitName[1].equals(scope))) {
			log.error("Invalid UPN scope.  Expected (" + scope + "), but received (" + splitName[1] + ").");
			throw new InvalidNameIdentifierException("Name Identifier does not contain a valid UPN.", null);
		}
		if (splitName[0] == null || splitName[0].equals("")) {
			log.error("Improper UPN formatting.  Unable to parse local principal.");
			throw new InvalidNameIdentifierException("Name Identifier does not contain a valid UPN.", null);
		}

		return new LocalPrincipal(splitName[0]);
	}

	public SAMLNameIdentifier getNameIdentifier(LocalPrincipal principal, ServiceProvider sProv, IdentityProvider idProv)
			throws NameIdentifierMappingException {

		if (principal == null) {
			log.error("A principal must be supplied for Name Identifier creation.");
			throw new IllegalArgumentException("A principal must be supplied for Name Identifier creation.");
		}

		try {
			SAMLNameIdentifier nameid = SAMLNameIdentifier.getInstance(getNameIdentifierFormat().toString());
			nameid.setName(principal.getName() + "@" + scope);
			nameid.setNameQualifier(idProv.getProviderId());
			return nameid;
		} catch (SAMLException e) {
			throw new NameIdentifierMappingException("Unable to generate Name Identifier: " + e);
		}
	}
}