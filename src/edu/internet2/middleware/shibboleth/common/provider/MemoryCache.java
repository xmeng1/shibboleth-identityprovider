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

package edu.internet2.middleware.shibboleth.common.provider;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import org.apache.log4j.Logger;

import edu.internet2.middleware.shibboleth.common.Cache;
import edu.internet2.middleware.shibboleth.common.CacheException;

/**
 * <code>Cache</code> implementation that uses java objects to cache data. This implementation will reap expired
 * entries.
 * 
 * @author Walter Hoehn
 */

public class MemoryCache extends BaseCache implements Cache {

	private MemoryCacheCleaner cleaner = new MemoryCacheCleaner();
	private static Logger log = Logger.getLogger(MemoryCache.class.getName());
	private Map<String, CacheEntry> entries = Collections.synchronizedMap(new HashMap<String, CacheEntry>());

	public MemoryCache(String name) {

		super(name, Cache.CacheType.SERVER_SIDE);
	}

	public boolean contains(String key) throws CacheException {

		CacheEntry entry = entries.get(key);
		if (entry == null) { return false; }

		// Clean cache if it is expired
		if (entry.isExpired()) {
			log.debug("Found expired object.  Deleting...");
			entries.remove(key);
			return false;
		}

		// OK, we have it
		return true;
	}

	public void remove(String key) throws CacheException {

		entries.remove(key);
	}

	public String retrieve(String key) throws CacheException {

		CacheEntry entry = entries.get(key);
		if (entry == null) { return null; }

		// Clean cache if it is expired
		if (entry.isExpired()) {
			log.debug("Found expired object.  Deleting...");
			entries.remove(key);
			return null;
		}

		return entry.value;
	}

	public void store(String key, String value, long duration) throws CacheException {

		entries.put(key, new CacheEntry(value, duration));
	}

	protected void destroy() {

		synchronized (cleaner) {
			if (cleaner != null) {
				cleaner.shutdown = true;
				cleaner.interrupt();
			}
		}
	}

	protected void finalize() throws Throwable {

		super.finalize();
		destroy();
	}

	private class MemoryCacheCleaner extends Thread {

		private boolean shutdown = false;
		private Thread master;

		private MemoryCacheCleaner() {

			super("edu.internet2.middleware.shibboleth.idp.common.provider.MemoryCache.MemoryCacheCleaner");
			this.master = Thread.currentThread();
			setDaemon(true);
			if (getPriority() > Thread.MIN_PRIORITY) {
				setPriority(getPriority() - 1);
			}
			log.debug("Starting memory-based cache cleanup thread (" + getName() + ").");
			start();
		}

		public void run() {

			try {
				sleep(60 * 1000); // one minute
			} catch (InterruptedException e) {
				log.debug("Memory-based cache cleanup interrupted (" + getName() + ").");
			}
			while (true) {
				try {
					if (!master.isAlive()) {
						shutdown = true;
						log.debug("Memory-based cache cleaner is orphaned (" + getName() + ").");
					}
					if (shutdown) {
						log.debug("Stopping Memory-based cache cleanup thread (" + getName() + ").");
						return;
					}
					log.debug("Memory-based cache cleanup thread searching for stale entries (" + getName() + ").");
					Set<String> needsDeleting = new HashSet<String>();
					synchronized (entries) {
						Iterator<Entry<String, CacheEntry>> iterator = entries.entrySet().iterator();
						while (iterator.hasNext()) {
							Entry<String, CacheEntry> entry = iterator.next();
							CacheEntry cacheEntry = entry.getValue();
							if (cacheEntry.isExpired()) {
								needsDeleting.add(entry.getKey());
							}
						}

					}
					// release the lock to be friendly
					Iterator deleteIterator = needsDeleting.iterator();
					while (deleteIterator.hasNext()) {
						synchronized (entries) {
							log.debug("Expiring an entry from the memory cache (" + getName() + ").");
							entries.remove(deleteIterator.next());
						}
					}
					sleep(60 * 1000); // one minute
				} catch (InterruptedException e) {
					log.debug("Memory-based cache cleanup interrupted (" + getName() + ").");
				}
			}
		}
	}
}
