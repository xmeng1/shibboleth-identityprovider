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

import java.io.IOException;
import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.ParserConfigurationException;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import edu.internet2.middleware.shibboleth.aa.arp.Arp;
import edu.internet2.middleware.shibboleth.aa.arp.ArpMarshallingException;
import edu.internet2.middleware.shibboleth.aa.arp.ArpRepository;
import edu.internet2.middleware.shibboleth.aa.arp.ArpRepositoryException;

/**
 * Provides marshalling/unmarshalling functionality common among <code>ArpRepository</code> implementations.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */

public abstract class BaseArpRepository implements ArpRepository {

	private static Logger log = Logger.getLogger(BaseArpRepository.class.getName());
	private ArpCache arpCache;

	BaseArpRepository(Element config) throws ArpRepositoryException {

		String rawArpTTL = config.getAttribute("arpTTL");
		long arpTTL = 0;
		try {
			if (rawArpTTL != null && !rawArpTTL.equals("")) {
				arpTTL = Long.parseLong(rawArpTTL);
				log.debug("ARP TTL set to: (" + arpTTL + ").");
			}
		} catch (NumberFormatException e) {
			log.error("ARP TTL must be set to a long integer.");
		}

		if (arpTTL > 0) {
			arpCache = ArpCache.instance();
			arpCache.setCacheLength(arpTTL);
		}
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.arp.ArpRepository#getAllPolicies(Principal)
	 */

	public Arp[] getAllPolicies(Principal principal) throws ArpRepositoryException {

		log.debug("Received a query for all policies applicable to principal: (" + principal.getName() + ").");
		Set<Arp> allPolicies = new HashSet<Arp>();
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
			if (xml == null) { return null; }

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
		} catch (ParserConfigurationException e) {
			log.error("An error occurred while loading the XML parser: " + e);
			throw new ArpRepositoryException("An error occurred while loading the XML parser.");
		}
	}

	/**
	 * Inheritors must return the site Arp as an xml element.
	 * 
	 * @return Element
	 */
	protected abstract Element retrieveSiteArpXml() throws IOException, SAXException, ParserConfigurationException;

	public void destroy() {

		if (arpCache != null) {
			arpCache.destroy();
		}
	}

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
			if (xml == null) { return null; }

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
		} catch (ParserConfigurationException e) {
			log.error("An error occurred while loading the XML parser: " + e);
			throw new ArpRepositoryException("An error occurred while loading the XML parser.");
		}
	}

	/**
	 * Inheritors must return the user Arp as an xml element.
	 * 
	 * @return Element
	 */
	protected abstract Element retrieveUserArpXml(Principal principal) throws IOException, SAXException,
			ParserConfigurationException;

}

class ArpCache {

	private static ArpCache instance = null;
	/** Time in seconds for which ARPs should be cached. */
	private long cacheLength;
	private Map<Principal, CachedArp> cache = new HashMap<Principal, CachedArp>();
	private static Logger log = Logger.getLogger(ArpCache.class.getName());
	private ArpCacheCleaner cleaner = new ArpCacheCleaner();

	protected ArpCache() {

	}

	static synchronized ArpCache instance() {

		if (instance == null) {
			instance = new ArpCache();
			return instance;
		}
		return instance;
	}

	/** Set time in seconds for which ARPs should be cached. */
	void setCacheLength(long cacheLength) {

		this.cacheLength = cacheLength;
	}

	void cache(Arp arp) {

		if (arp.isSitePolicy() == false) {
			synchronized (cache) {
				cache.put(arp.getPrincipal(), new CachedArp(arp, System.currentTimeMillis()));
			}
		} else {
			synchronized (cache) {
				cache.put(new SiteCachePrincipal(), new CachedArp(arp, System.currentTimeMillis()));
			}
		}
	}

	Arp retrieveUserArpFromCache(Principal principal) {

		return retrieveArpFromCache(principal);
	}

	Arp retrieveSiteArpFromCache() {

		return retrieveArpFromCache(new SiteCachePrincipal());
	}

	private Arp retrieveArpFromCache(Principal principal) {

		CachedArp cachedArp;
		synchronized (cache) {
			cachedArp = (CachedArp) cache.get(principal);
		}

		if (cachedArp == null) { return null; }

		if ((System.currentTimeMillis() - cachedArp.creationTimeMillis) < (cacheLength * 1000)) { return cachedArp.arp; }

		synchronized (cache) {
			cache.remove(principal);
		}
		return null;
	}

	/**
	 * @see java.lang.Object#finalize()
	 */
	protected void finalize() throws Throwable {

		super.finalize();
		destroy();
	}

	public void destroy() {

		synchronized (cleaner) {
			if (cleaner != null) {
				cleaner.shutdown = true;
				cleaner.interrupt();
			}
		}
	}

	private class CachedArp {

		Arp arp;
		long creationTimeMillis;

		CachedArp(Arp arp, long creationTimeMillis) {

			this.arp = arp;
			this.creationTimeMillis = creationTimeMillis;
		}
	}

	private class SiteCachePrincipal implements Principal {

		public String getName() {

			return "ARP admin";
		}

		/**
		 * @see java.lang.Object#equals(Object)
		 */
		public boolean equals(Object object) {

			if (object instanceof SiteCachePrincipal) { return true; }
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

	private class ArpCacheCleaner extends Thread {

		private boolean shutdown = false;
		private Thread master;

		public ArpCacheCleaner() {

			super("edu.internet2.middleware.shibboleth.aa.arp.provider.BaseArpRepository.ArpCache.ArpCacheCleaner");
			master = Thread.currentThread();
			setDaemon(true);
			if (getPriority() > Thread.MIN_PRIORITY) {
				setPriority(getPriority() - 1);
			}
			log.debug("Starting ArpCache Cleanup Thread.");
			start();
		}

		public void run() {

			try {
				sleep(60 * 1000); // one minute
			} catch (InterruptedException e) {
				log.debug("ArpCache Cleanup interrupted.");
			}
			while (true) {
				try {
					if (master == null) {
						log.debug("ArpCache cache cleaner is orphaned.");
						shutdown = true;
					}
					if (shutdown) {
						log.debug("Stopping ArpCache Cleanup Thread.");
						return;
					}
					log.debug("ArpCache cleanup thread searching for stale entries.");
					Set<CachedArp> needsDeleting = new HashSet<CachedArp>();
					synchronized (cache) {
						Iterator<CachedArp> iterator = cache.values().iterator();
						while (iterator.hasNext()) {
							CachedArp cachedArp = iterator.next();
							if ((System.currentTimeMillis() - cachedArp.creationTimeMillis) > (cacheLength * 1000)) {
								needsDeleting.add(cachedArp);
							}
						}
					}
					// release the lock to be friendly
					Iterator deleteIterator = needsDeleting.iterator();
					while (deleteIterator.hasNext()) {
						synchronized (cache) {
							CachedArp cachedArp = (CachedArp) deleteIterator.next();
							if (cachedArp.arp.isSitePolicy()) {
								log.debug("Expiring site ARP from the Cache.");
								cache.remove(new SiteCachePrincipal());
							} else {
								log.debug("Expiring an ARP from the Cache.");
								cache.remove(cachedArp.arp.getPrincipal());
							}
						}
					}

					sleep(60 * 1000); // one minute
				} catch (InterruptedException e) {
					log.debug("ArpCache Cleanup interrupted.");
				}
			}
		}
	}

}
