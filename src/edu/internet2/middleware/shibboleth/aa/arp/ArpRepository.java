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

package edu.internet2.middleware.shibboleth.aa.arp;

import java.security.Principal;

/**
 * Defines interaction with an <code>Arp</code> storage/retrieval mechanism.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */

public interface ArpRepository {

	/**
	 * Searches the repository for all Attribute Release Policies associated with the named <code>Principal</code>
	 * 
	 * @return instances of <code>Arp</code> or null if no associated policies are found in the repository
	 */

	public Arp[] getAllPolicies(Principal principal) throws ArpRepositoryException;

	/**
	 * Retrieves the "User" Attribute Release Policy associated with the named <code>Principal</code>
	 * 
	 * @return aninstance of <code>Arp</code> or null if no User policy is found in the repository for the
	 *         <code>Principal</code>
	 */

	public Arp getUserPolicy(Principal principal) throws ArpRepositoryException;

	/**
	 * Retrieves the "Site" Attribute Release Policy
	 * 
	 * @return an instance of <code>Arp</code> or null if no Site policy is defined in the repository
	 */

	public Arp getSitePolicy() throws ArpRepositoryException;

	/**
	 * If a matching <code>Arp</code> is found in the repository, it is replaced with the specified <code>Arp</code>.
	 * If not, the <code>Arp</code> is added to the repository.
	 */

	public void update(Arp arp) throws ArpRepositoryException;

	/**
	 * Removes the specified <code>Arp</code> from the repository if it exists
	 */

	public void remove(Arp arp) throws ArpRepositoryException;

	/**
	 * Cleanup resources that won't be released when this object is garbage-collected
	 */
	public void destroy();

}
