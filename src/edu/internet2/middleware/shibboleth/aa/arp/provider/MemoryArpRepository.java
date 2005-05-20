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

package edu.internet2.middleware.shibboleth.aa.arp.provider;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.arp.Arp;
import edu.internet2.middleware.shibboleth.aa.arp.ArpRepository;
import edu.internet2.middleware.shibboleth.aa.arp.ArpRepositoryException;

/**
 * A memory-based <code>ArpRepository</code> implementation. Only useful for testing.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */

public class MemoryArpRepository implements ArpRepository {

	private Map userPolicies = Collections.synchronizedMap(new HashMap());
	private Arp sitePolicy;
	private static Logger log = Logger.getLogger(MemoryArpRepository.class.getName());

	public MemoryArpRepository(Element config) {

	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.arp.ArpRepository#getSitePolicy()
	 */

	public synchronized Arp getSitePolicy() throws ArpRepositoryException {

		return sitePolicy;
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.arp.ArpRepository#getAllPolicies(Principal)
	 */

	public Arp[] getAllPolicies(Principal principal) throws ArpRepositoryException {

		log.debug("Received a query for all policies applicable to principal: (" + principal.getName() + ").");
		Set allPolicies = new HashSet();
		if (getSitePolicy() != null) {
			log.debug("Returning site policy.");
			allPolicies.add(getSitePolicy());
		}
		if (getUserPolicy(principal) != null) {
			allPolicies.add(getUserPolicy(principal));
			log.debug("Returning user policy.");
		}
		if (allPolicies.isEmpty()) {
			log.debug("No policies found.");
		}
		return (Arp[]) allPolicies.toArray(new Arp[0]);
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.arp.ArpRepository#getUserPolicy(Principal)
	 */

	public Arp getUserPolicy(Principal principal) throws ArpRepositoryException {

		return (Arp) userPolicies.get(principal);
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.arp.ArpRepository#remove(Arp)
	 */

	public void remove(Arp arp) throws ArpRepositoryException {

		if (arp.isSitePolicy()) {
			synchronized (this) {
				sitePolicy = null;
			}
		} else if (userPolicies.containsKey(arp.getPrincipal())) {
			userPolicies.remove(arp.getPrincipal());
		}
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.arp.ArpRepository#update(Arp)
	 */

	public void update(Arp arp) throws ArpRepositoryException {

		if (arp == null) { throw new ArpRepositoryException("Cannot add a null ARP to the repository."); }

		if (arp.isSitePolicy()) {
			synchronized (this) {
				sitePolicy = arp;
			}
			return;
		}

		if (arp.getPrincipal() == null) { throw new ArpRepositoryException(
				"Cannot add ARP to repository.  Must contain a Principal or be a Site ARP."); }

		userPolicies.put(arp.getPrincipal(), arp);
	}

	public void destroy() {

	// do nothing
	}

}
