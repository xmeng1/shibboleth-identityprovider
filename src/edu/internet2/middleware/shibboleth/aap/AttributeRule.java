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

package edu.internet2.middleware.shibboleth.aap;

import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLException;

import edu.internet2.middleware.shibboleth.metadata.RoleDescriptor;

/**
 * Specifies handling of a specific SAML attribute
 * 
 * @author Scott Cantor
 */
public interface AttributeRule {

	/**
	 * Get the SAML name of the applicable attribute
	 * 
	 * @return The AttributeName
	 */
	String getName();

	/**
	 * Get the SAML namespace of the applicable attribute
	 * 
	 * @return The AttributeNamespace
	 */
	String getNamespace();

	/**
	 * Get the shorthand name of the attribute
	 * 
	 * @return The shorthand name
	 */
	String getAlias();

	/**
	 * Get the name of the protocol-specific header to export the attribute into
	 * 
	 * @return The header name
	 */
	String getHeader();

	/**
	 * Is value matching of this attribute case-sensitive?
	 * 
	 * @return The case sensitivity of the values
	 */
	boolean getCaseSensitive();

	/**
	 * Is the attribute formally scoped?
	 * 
	 * @return The scoped property
	 */
	boolean getScoped();

	/**
	 * Applies a rule to an attribute, taking into account the role in which the issuer was acting
	 * 
	 * @param attribute
	 *            The attribute to apply the filtering rule to
	 * @param role
	 *            The metadata role in which the attribute issuer is acting
	 * @throws SAMLException
	 *             Raised if the attribute is no longer valid after the filtering process (generally if all values are
	 *             deleted)
	 */
	void apply(SAMLAttribute attribute, RoleDescriptor role) throws SAMLException;
}
