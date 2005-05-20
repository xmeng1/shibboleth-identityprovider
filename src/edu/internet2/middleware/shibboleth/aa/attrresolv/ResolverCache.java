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

package edu.internet2.middleware.shibboleth.aa.attrresolv;

import java.security.Principal;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Set;

import javax.naming.directory.Attributes;

import org.apache.log4j.Logger;

/**
 * Rudimentary mechanism for caching objects created by the various Resolution PlugIns.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 * 
 */
public class ResolverCache {

	private static Logger log = Logger.getLogger(ResolverCache.class.getName());
	// Hashtable handles synchronization for us
	private Hashtable attributeDataCache = new Hashtable();
	private Hashtable connectorDataCache = new Hashtable();
	private Cleaner cleaner = new Cleaner();

	ResolverCache() {

		log.info("Initializing the Attribute Resolver cache.");
	}

	void cacheConnectorResolution(Principal principal, String plugInId, long cacheLength, Attributes toCache) {

		if (principal != null && cacheLength > 0 && plugInId != null && !plugInId.equals("") && toCache != null) {
			log.debug("Adding resolved Connector data to Attribute Resolver cache.");
			connectorDataCache.put(new CacheKey(principal, plugInId), new CacheObject(toCache, System
					.currentTimeMillis()
					+ (cacheLength * 1000)));

		} else {
			log.error("Attempted to add bad data to Attribute Resolver cache.");
		}
	}

	void cacheAttributeResolution(Principal principal, String plugInId, long cacheLength, ResolverAttribute toCache) {

		if (principal != null && cacheLength > 0 && plugInId != null && !plugInId.equals("") && toCache != null) {
			log.debug("Adding resolved Attribute data to Attribute Resolver cache.");
			attributeDataCache.put(new CacheKey(principal, plugInId), new CacheObject(toCache, System
					.currentTimeMillis()
					+ (cacheLength * 1000)));

		} else {
			log.error("Attempted to add bad data to Attribute Resolver cache.");
		}
	}

	ResolverAttribute getResolvedAttribute(Principal principal, String plugInId) {

		log.debug("Searching Cache for resolved attribute.");
		Object object = attributeDataCache.get(new CacheKey(principal, plugInId));
		if (object == null) {
			log.debug("No match found.");
			return null;
		} else {
			CacheObject cacheObject = (CacheObject) object;
			if (cacheObject.isExpired()) {
				deleteAttributeResolution(new CacheKey(principal, plugInId));
				log.debug("Cached entry is expired.");
				return null;
			} else {
				log.debug("Located cached entry.");
				return (ResolverAttribute) cacheObject.getCached();
			}
		}
	}

	Attributes getResolvedConnector(Principal principal, String plugInId) {

		log.debug("Searching Cache for resolved connector.");
		Object object = connectorDataCache.get(new CacheKey(principal, plugInId));
		if (object == null) {
			log.debug("No match found.");
			return null;
		} else {
			CacheObject cacheObject = (CacheObject) object;
			if (cacheObject.isExpired()) {
				deleteConnectorResolution(new CacheKey(principal, plugInId));
				log.debug("Cached entry is expired.");
				return null;
			} else {
				log.debug("Located cached entry.");
				return (Attributes) cacheObject.getCached();
			}
		}
	}

	private void deleteAttributeResolution(CacheKey cacheKey) {

		synchronized (attributeDataCache) {
			Object object = attributeDataCache.get(cacheKey);
			if (object != null) {
				CacheObject cacheObject = (CacheObject) object;
				if (cacheObject.isExpired()) {
					attributeDataCache.remove(cacheKey);
				}
			}

		}
	}

	private void deleteConnectorResolution(CacheKey cacheKey) {

		synchronized (connectorDataCache) {
			Object object = connectorDataCache.get(cacheKey);
			if (object != null) {
				CacheObject cacheObject = (CacheObject) object;
				if (cacheObject.isExpired()) {
					connectorDataCache.remove(cacheKey);
				}
			}

		}
	}

	/**
	 * @see java.lang.Object#finalize()
	 */
	protected void finalize() throws Throwable {

		super.finalize();
		destroy();
	}

	/**
	 * Cleanup resources that won't be released when this object is garbage-collected
	 */
	protected void destroy() {

		synchronized (cleaner) {
			if (cleaner != null) {
				cleaner.shutdown = true;
				cleaner.interrupt();
			}
		}
	}

	private class CacheObject {

		Object object;
		long expiration;

		private CacheObject(Object object, long expiration) {

			this.object = object;
			this.expiration = expiration;
		}

		private Object getCached() {

			return object;
		}

		private boolean isExpired() {

			if (System.currentTimeMillis() > expiration) {
				return true;
			} else {
				return false;
			}
		}
	}

	private class CacheKey {

		private Principal principal;
		private String plugInId;

		private CacheKey(Principal principal, String plugInId) {

			if (principal == null || plugInId == null) { throw new IllegalArgumentException(
					"Cannot use null value in as cache key."); }
			this.principal = principal;
			this.plugInId = plugInId;
		}

		/**
		 * @see java.lang.Object#equals(Object)
		 */
		public boolean equals(Object object) {

			if (object == null || !(object instanceof CacheKey)) { return false; }
			if (!plugInId.equals(((CacheKey) object).getPlugInId())) { return false; }
			if (!principal.equals(((CacheKey) object).getPrincipal())) { return false; }
			return true;
		}

		/**
		 * Method getPlugInId.
		 * 
		 * @return Object
		 */
		private String getPlugInId() {

			return plugInId;
		}

		/**
		 * Method getPrincipal.
		 * 
		 * @return Object
		 */
		private Principal getPrincipal() {

			return principal;
		}

		/**
		 * @see java.lang.Object#hashCode()
		 */
		public int hashCode() {

			return (principal.hashCode() + ":" + plugInId.hashCode()).hashCode();
		}

	}

	private class Cleaner extends Thread {

		private boolean shutdown = false;
		private Object master;

		public Cleaner() {

			super("edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverCacher.Cleaner");
			master = Thread.currentThread();
			setDaemon(true);
			if (getPriority() > Thread.MIN_PRIORITY) {
				setPriority(getPriority() - 1);
			}
			log.debug("Starting Resolver Cache cleanup thread.");
			start();
		}

		public void run() {

			try {
				sleep(60 * 1000); // one minute
			} catch (InterruptedException e) {
				log.debug("Resolver Cache Cleanup interrupted.");
			}

			while (true) {
				try {
					if (master == null) {
						log.debug("Resolver cache cleaner is orphaned.");
						shutdown = true;
					}
					if (shutdown) {
						log.debug("Stopping Resolver cache cleanup thread.");
						return;
					}

					log.debug("Resolver Cache cleanup thread searching cache for stale entries.");
					Hashtable[] caches = {attributeDataCache, connectorDataCache};

					for (int i = 0; i < caches.length; i++) {
						Set stale = new HashSet();
						synchronized (caches[i]) {
							Set keySet = caches[i].keySet();
							Iterator cachedAttributes = keySet.iterator();
							while (cachedAttributes.hasNext()) {
								CacheKey key = (CacheKey) cachedAttributes.next();
								CacheObject object = (CacheObject) caches[i].get(key);
								if (object != null && object.isExpired()) {
									log.debug("Found a stale resolution in the cache.");
									stale.add(key);
								}
							}
						}

						synchronized (caches[i]) {
							if (!stale.isEmpty()) {
								Iterator stales = stale.iterator();
								while (stales.hasNext()) {
									log.debug("Expiring stale Resolutions from the Cache.");
									Object removed = caches[i].remove(stales.next());
									if (removed != null) {
										log.debug("Entry expired.");
									} else {
										log.debug("Couldn't expire entry.  Not found in cache.");
									}
								}
							}
						}
					}

					sleep(60 * 1000); // one minute

				} catch (InterruptedException e) {
					log.debug("Resolver Cache Cleanup interrupted.");
				}
			}
		}
	}
}
