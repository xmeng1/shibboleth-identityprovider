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

package edu.internet2.middleware.shibboleth.aa.attrresolv;

import java.security.Principal;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Set;

import javax.naming.directory.Attributes;

import org.apache.log4j.Logger;

/**
 * Rudimentary mechanism for caching objects created by the various
 * Resolution PlugIns.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 *
 */
public class ResolverCache {

	private static Logger log = Logger.getLogger(ResolverCache.class.getName());
	//Hashtable handles synchronization for us
	private Hashtable attributeDataCache = new Hashtable();
	private Hashtable connectorDataCache = new Hashtable();
	private Cleaner cleaner = new Cleaner(Thread.currentThread());

	ResolverCache() {
		log.info("Initializing the Attribute Resolver cache.");
	}

	void cacheConnectorResolution(Principal principal, String plugInId, long cacheLength, Attributes toCache) {

		if (principal != null && cacheLength > 0 && plugInId != null && !plugInId.equals("") && toCache != null) {
			log.debug("Adding resolved Connector data to Attribute Resolver cache.");
			connectorDataCache.put(
				new CacheKey(principal, plugInId),
				new CacheObject(toCache, System.currentTimeMillis() + (cacheLength * 1000)));

		} else {
			log.error("Attempted to add bad data to Attribute Resolver cache.");
		}
	}

	void cacheAttributeResolution(Principal principal, String plugInId, long cacheLength, ResolverAttribute toCache) {

		if (principal != null && cacheLength > 0 && plugInId != null && !plugInId.equals("") && toCache != null) {
			log.debug("Adding resolved Attribute data to Attribute Resolver cache.");
			attributeDataCache.put(
				new CacheKey(principal, plugInId),
				new CacheObject(toCache, System.currentTimeMillis() + (cacheLength * 1000)));

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
		synchronized (cleaner) {
			cleaner.shutdown = true;
			cleaner.interrupt();
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
			if (principal == null || plugInId == null) {
				throw new IllegalArgumentException("Cannot use null value in as cache key.");
			}
			this.principal = principal;
			this.plugInId = plugInId;
		}
		/**
		 * @see java.lang.Object#equals(Object)
		 */
		public boolean equals(Object object) {
			if (object == null || !(object instanceof CacheKey)) {
				return false;
			}
			if (!plugInId.equals(((CacheKey) object).getPlugInId())) {
				return false;
			}
			if (!principal.equals(((CacheKey) object).getPrincipal())) {
				return false;
			}
			return true;
		}

		/**
		 * Method getPlugInId.
		 * @return Object
		 */
		private String getPlugInId() {
			return plugInId;
		}

		/**
		 * Method getPrincipal.
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
		private Thread master;

		public Cleaner(Thread master) {
			super();
			log.debug("Starting Resolver Cache cleanup thread.");
			this.master = master;
			setDaemon(true);
			start();
		}

		public void run() {
			try {
				sleep(5 * 60 * 1000);
			} catch (InterruptedException e) {
				log.debug("Resolver Cache Cleanup interrupted.");
			}

			while (true) {
				try {
					if (!master.isAlive()) {
						shutdown = true;
					}
					if (shutdown) {
						log.debug("Stopping Resolver cache cleanup thread.");
						return;
					}

					log.debug("Resolver Cache cleanup thread searching cache for stale entries.");
					Hashtable[] caches = { attributeDataCache, connectorDataCache };

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

					sleep(5 * 60 * 1000);

				} catch (InterruptedException e) {
					log.debug("Resolver Cache Cleanup interrupted.");
				}
			}
		}
	}
}
