/* 
 * The Shibboleth License, Version 1. 
 * Copyright (c) 2002 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
 * 
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this 
 * list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution, if any, must include 
 * the following acknowledgment: "This product includes software developed by 
 * the University Corporation for Advanced Internet Development 
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement 
 * may appear in the software itself, if and wherever such third-party 
 * acknowledgments normally appear.
 * 
 * Neither the name of Shibboleth nor the names of its contributors, nor 
 * Internet2, nor the University Corporation for Advanced Internet Development, 
 * Inc., nor UCAID may be used to endorse or promote products derived from this 
 * software without specific prior written permission. For written permission, 
 * please contact shibboleth@shibboleth.org
 * 
 * Products derived from this software may not be called Shibboleth, Internet2, 
 * UCAID, or the University Corporation for Advanced Internet Development, nor 
 * may Shibboleth appear in their name, without prior written permission of the 
 * University Corporation for Advanced Internet Development.
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK 
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY 
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.aa.arp.provider;

import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.apache.log4j.Logger;

import edu.internet2.middleware.shibboleth.aa.arp.Arp;
import edu.internet2.middleware.shibboleth.aa.arp.ArpRepository;
import edu.internet2.middleware.shibboleth.aa.arp.ArpRepositoryException;

/**
 * A memory-based <code>ArpRepository</code> implementation.  Only useful for testing.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */

public class MemoryArpRepository implements ArpRepository {

	private Map userPolicies = Collections.synchronizedMap(new HashMap());
	private Arp sitePolicy;
	private static Logger log = Logger.getLogger(MemoryArpRepository.class.getName());

	public MemoryArpRepository(Properties props) {
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
		log.debug(
			"Received a query for all policies applicable to principal: ("
				+ principal.getName()
				+ ").");
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

		if (arp == null) {
			throw new ArpRepositoryException("Cannot add a null ARP to the repository.");
		}

		if (arp.isSitePolicy()) {
			synchronized (this) {
				sitePolicy = arp;
			}
			return;
		}

		if (arp.getPrincipal() == null) {
			throw new ArpRepositoryException("Cannot add ARP to repository.  Must contain a Principal or be a Site ARP.");
		}

		userPolicies.put(arp.getPrincipal(), arp);
	}

}
