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

package edu.internet2.middleware.shibboleth.hs.provider;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.Map.Entry;

import org.apache.log4j.Logger;
import org.doomdark.uuid.UUIDGenerator;

import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;
import edu.internet2.middleware.shibboleth.hs.HandleRepository;
import edu.internet2.middleware.shibboleth.hs.HandleRepositoryException;

/**
 * <code>HandleRepository</code> implementation that uses a static cache.  This requires
 * that the HS and AA run in the same JVM.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public class MemoryHandleRepository extends BaseHandleRepository implements HandleRepository {

	protected HandleCache cache = HandleCache.instance();
	private static Logger log = Logger.getLogger(MemoryHandleRepository.class.getName());

	public MemoryHandleRepository(Properties properties) throws HandleRepositoryException {
		super(properties);
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.hs.HandleRepository#getHandle(Principal)
	 */
	public String getHandle(AuthNPrincipal principal) {
		String handle = UUIDGenerator.getInstance().generateRandomBasedUUID().toString();
		log.debug("Assigning handle (" + handle + ") to principal (" + principal.getName() + ").");
		synchronized (cache.handleEntries) {
			cache.handleEntries.put(handle, createHandleEntry(principal));
		}
		return handle;
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.hs.HandleRepository#getPrincipal(String)
	 */
	public AuthNPrincipal getPrincipal(String handle) {
		synchronized (cache.handleEntries) {
			if (!cache.handleEntries.containsKey(handle)) {
				log.debug("Repository does not contain an entry for this Attribute Query Handle.");
				return null;
			}
		}
		HandleEntry handleEntry;
		synchronized (cache.handleEntries) {
			handleEntry = (HandleEntry) cache.handleEntries.get(handle);
		}
		if (handleEntry.isExpired()) {
			log.debug("Attribute Query Handle is expired.");
			synchronized (cache.handleEntries) {
				cache.handleEntries.remove(handle);
			}
			return null;
		} else {
			log.debug("Attribute Query Handle recognized.");
			return handleEntry.principal;
		}
	}
}
class HandleCache {

	protected Map handleEntries = new HashMap();
	private static HandleCache instance;
	protected MemoryRepositoryCleaner cleaner = new MemoryRepositoryCleaner();
	private static Logger log = Logger.getLogger(HandleCache.class.getName());

	protected HandleCache() {
	}

	public static synchronized HandleCache instance() {
		if (instance == null) {
			instance = new HandleCache();
			return instance;
		}
		return instance;
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

	private class MemoryRepositoryCleaner extends Thread {

		private boolean shutdown = false;

		public MemoryRepositoryCleaner() {
			super();
			log.debug("Starting Memory Repository Cleanup Thread.");
			start();
		}

		public void run() {
			try {
				sleep(1 * 60 * 1000);
			} catch (InterruptedException e) {
				log.debug("Memory Repository Cleanup interrupted.");
			}
			while (true) {
				try {
					if (shutdown) {
						log.debug("Stopping Memory Repository Cleanup Thread.");
						return;
					}
					Set needsDeleting = new HashSet();
					synchronized (handleEntries) {
						Iterator iterator = handleEntries.entrySet().iterator();
						while (iterator.hasNext()) {
							Entry entry = (Entry) iterator.next();
							HandleEntry handleEntry = (HandleEntry) entry.getValue();
							if (handleEntry.isExpired()) {
								needsDeleting.add(entry.getKey());
							}
						}
						//release the lock to be friendly
						Iterator deleteIterator = needsDeleting.iterator();
						while (deleteIterator.hasNext()) {
							synchronized (handleEntries) {
								log.debug("Expiring an Attribute Query Handle from the Memory Repository.");
								handleEntries.remove(deleteIterator.next());
							}
						}
					}
					sleep(1 * 60 * 1000);
				} catch (InterruptedException e) {
					log.debug("Memory Repository Cleanup interrupted.");
				}
			}
		}
	}

}
