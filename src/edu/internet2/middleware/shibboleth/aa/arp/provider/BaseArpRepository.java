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

import java.io.IOException;
import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import edu.internet2.middleware.shibboleth.aa.arp.Arp;
import edu.internet2.middleware.shibboleth.aa.arp.ArpMarshallingException;
import edu.internet2.middleware.shibboleth.aa.arp.ArpRepository;
import edu.internet2.middleware.shibboleth.aa.arp.ArpRepositoryException;

/**
 * Provides marshalling/unmarshalling functionality common among 
 * <code>ArpRepository</code> implementations.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */

public abstract class BaseArpRepository implements ArpRepository {

	private static Logger log = Logger.getLogger(BaseArpRepository.class.getName());
	private ArpCache arpCache;

	BaseArpRepository(Properties properties) {
		if (properties
			.getProperty(
				"edu.internet2.middleware.shibboleth.aa.arp.BaseArpRepository.ArpTTL",
				null)
			!= null) {
			arpCache = ArpCache.instance();
			arpCache.setCacheLength(
				Long.parseLong(
					properties.getProperty(
						"edu.internet2.middleware.shibboleth.aa.arp.BaseArpRepository.ArpTTL",
						null)));
		}
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
		Arp sitePolicy = getSitePolicy();
		if (sitePolicy != null) {
			log.debug("Returning site policy.");
			allPolicies.add(sitePolicy);
		}
		
		Arp userPolicy = getUserPolicy(principal);
		if (userPolicy != null) {
			allPolicies.add(userPolicy);
			log.debug("Returning user policy.");
		}
		if (allPolicies.isEmpty()) {
			log.debug("No policies found.");
		}
		return (Arp[]) allPolicies.toArray(new Arp[0]);
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.arp.ArpRepository#getSitePolicy()
	 */
	public Arp getSitePolicy() throws ArpRepositoryException {

		try {
			if (arpCache != null) {
				Arp cachedArp = arpCache.retrieveSiteArpFromCache();
				if (cachedArp != null) {
					log.debug("Using cached site ARP.");
					return cachedArp;
				}
			}

			Element xml = retrieveSiteArpXml();
			if (xml == null) {
				return null;
			}

			Arp siteArp = new Arp();
			siteArp.marshall(xml);
			if (arpCache != null) {
				arpCache.cache(siteArp);
			}
			return siteArp;
		} catch (ArpMarshallingException ame) {
			log.error("An error occurred while marshalling an ARP: " + ame);
			throw new ArpRepositoryException("An error occurred while marshalling an ARP.");
		} catch (IOException ioe) {
			log.error("An error occurred while loading an ARP: " + ioe);
			throw new ArpRepositoryException("An error occurred while loading an ARP.");
		} catch (SAXException se) {
			log.error("An error occurred while parsing an ARP: " + se);
			throw new ArpRepositoryException("An error occurred while parsing an ARP.");
		}
	}

	/**
	 * Inheritors must return the site Arp as an xml element.
	 * @return Element
	 */
	protected abstract Element retrieveSiteArpXml() throws IOException, SAXException;

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.arp.ArpRepository#getUserPolicy(Principal)
	 */
	public Arp getUserPolicy(Principal principal) throws ArpRepositoryException {

		if (arpCache != null) {
			Arp cachedArp = arpCache.retrieveUserArpFromCache(principal);
			if (cachedArp != null) {
				log.debug("Using cached user ARP.");
				return cachedArp;
			}
		}

		try {
			Element xml = retrieveUserArpXml(principal);
			if (xml == null) {
				return null;
			}

			Arp userArp = new Arp();
			userArp.setPrincipal(principal);

			userArp.marshall(xml);
			if (arpCache != null) {
				arpCache.cache(userArp);
			}
			return userArp;
		} catch (ArpMarshallingException ame) {
			log.error("An error occurred while marshalling an ARP: " + ame);
			throw new ArpRepositoryException("An error occurred while marshalling an ARP.");
		} catch (IOException ioe) {
			log.error("An error occurred while loading an ARP: " + ioe);
			throw new ArpRepositoryException("An error occurred while loading an ARP.");
		} catch (SAXException se) {
			log.error("An error occurred while parsing an ARP: " + se);
			throw new ArpRepositoryException("An error occurred while parsing an ARP.");
		}
	}

	/**
	 * Inheritors must return the user Arp as an xml element.
	 * @return Element
	 */
	protected abstract Element retrieveUserArpXml(Principal principal)
		throws IOException, SAXException;

}

class ArpCache {

	private static ArpCache instance = null;
	private long cacheLength;
	private Map cache = new HashMap();

	protected ArpCache() {
	}

	static ArpCache instance() {
		if (instance == null) {
			return new ArpCache();
		}
		return instance;
	}

	void setCacheLength(long cacheLength) {
		this.cacheLength = cacheLength;
	}

	void cache(Arp arp) {
		if (arp.isSitePolicy() == false) {
			cache.put(arp.getPrincipal(), new CachedArp(arp, System.currentTimeMillis()));
		} else {
			cache.put(new SiteCachePrincipal(), new CachedArp(arp, System.currentTimeMillis()));
		}
	}

	Arp retrieveUserArpFromCache(Principal principal) {
		return retrieveArpFromCache(principal);
	}

	Arp retrieveSiteArpFromCache() {
		return retrieveArpFromCache(new SiteCachePrincipal());
	}

	private Arp retrieveArpFromCache(Principal principal) {
		CachedArp cachedArp = (CachedArp) cache.get(principal);
		if (cachedArp == null) {
			return null;
		}

		if ((System.currentTimeMillis() - cachedArp.creationTimeMillis) < cacheLength) {
			return cachedArp.arp;
		}
		cache.remove(principal);
		return null;
	}

	class CachedArp {
		Arp arp;
		long creationTimeMillis;

		CachedArp(Arp arp, long creationTimeMillis) {
			this.arp = arp;
			this.creationTimeMillis = creationTimeMillis;
		}
	}

	class SiteCachePrincipal implements Principal {

		public String getName() {
			return "ARP admin";
		}

		/**
		 * @see java.lang.Object#equals(Object)
		 */
		public boolean equals(Object object) {
			if (object instanceof SiteCachePrincipal) {
				return true;
			}
			return false;
		}

		/**
		 * @see java.lang.Object#hashCode()
		 */
		public int hashCode() {
			return "edu.internet2.middleware.shibboleth.aa.arp.provider.BaseArpRepository.SiteCachePrincipal"
				.hashCode();
		}
	}
}
