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

import java.util.Iterator;

/**
 * Interface to attribute acceptance policy
 * 
 * @author Scott Cantor
 */
public interface AAP {

	/**
	 * Determine whether this policy does not impose any filtering rules
	 * 
	 * @return true iff the policy does not contain any filtering rules
	 */
	boolean anyAttribute();

	/**
	 * Find a rule for the given SAML attribute
	 * 
	 * @param name
	 *            The AttributeName
	 * @param namespace
	 *            The AttributeNamespace
	 * @return The applicable rule, if any
	 */
	AttributeRule lookup(String name, String namespace);

	/**
	 * Find a rule for the given shorthand attribute name
	 * 
	 * @param alias
	 *            The shorthand name
	 * @return The applicable rule, if any
	 */
	AttributeRule lookup(String alias);

	/**
	 * Get all of the rules contained in the policy
	 * 
	 * @return The policy rules
	 */
	Iterator /* <AttributeRule> */getAttributeRules();
}
