/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation
 * for Advanced Internet Development, Inc. All rights reserved
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
 * <http://www.ucaid.edu> Internet2 Project. Alternately, this acknowledegement
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
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package edu.internet2.middleware.shibboleth.hs.provider;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import org.apache.log4j.Logger;
import org.doomdark.uuid.UUIDGenerator;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;
import edu.internet2.middleware.shibboleth.common.IdentityProvider;
import edu.internet2.middleware.shibboleth.common.InvalidNameIdentifierException;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMappingException;
import edu.internet2.middleware.shibboleth.common.ServiceProvider;
import edu.internet2.middleware.shibboleth.hs.HSNameIdentifierMapping;

/**
 * <code>HSNameIdentifierMapping</code> implementation that uses an in-memory
 * cache to store mappings between principal names and Shibboleth Attribute Query Handles.
 * 
 * @author Walter Hoehn
 */
public class SharedMemoryShibHandle extends AQHNameIdentifierMapping implements HSNameIdentifierMapping {

	protected HandleCache cache = HandleCache.instance();
	private static Logger log = Logger.getLogger(SharedMemoryShibHandle.class.getName());

	public SharedMemoryShibHandle(Element config) throws NameIdentifierMappingException {
		super(config);
	}

	public SAMLNameIdentifier getNameIdentifierName(
		AuthNPrincipal principal,
		ServiceProvider sProv,
		IdentityProvider idProv)
		throws NameIdentifierMappingException {

		if (principal == null) {
			log.error("A principal must be supplied for Attribute Query Handle creation.");
			throw new IllegalArgumentException("A principal must be supplied for Attribute Query Handle creation.");
		}

		String handle = UUIDGenerator.getInstance().generateRandomBasedUUID().toString();
		log.debug("Assigning handle (" + handle + ") to principal (" + principal.getName() + ").");
		synchronized (cache.handleEntries) {
			cache.handleEntries.put(handle, createHandleEntry(principal));
		}

		try {
			return new SAMLNameIdentifier(handle, idProv.getId(), getNameIdentifierFormat().toString());
		} catch (SAMLException e) {
			throw new NameIdentifierMappingException("Unable to generate Attribute Query Handle: " + e);
		}

	}

	public AuthNPrincipal getPrincipal(SAMLNameIdentifier nameId, ServiceProvider sProv, IdentityProvider idProv)
		throws NameIdentifierMappingException, InvalidNameIdentifierException {

		synchronized (cache.handleEntries) {
			if (!cache.handleEntries.containsKey(nameId.getName())) {
				log.debug("The Name Mapping Cache does not contain an entry for this Attribute Query Handle.");
				throw new NameIdentifierMappingException("The Name Mapping Cache does not contain an entry for this Attribute Query Handle.");
			}
		}

		HandleEntry handleEntry;
		synchronized (cache.handleEntries) {
			handleEntry = (HandleEntry) cache.handleEntries.get(nameId.getName());
		}

		if (handleEntry.isExpired()) {
			log.debug("Attribute Query Handle is expired.");
			synchronized (cache.handleEntries) {
				cache.handleEntries.remove(nameId.getName());
			}
			throw new InvalidNameIdentifierException("Attribute Query Handle is expired.");
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
			log.debug("Starting memory-based shib handle cache cleanup thread.");
			start();
		}

		public void run() {
			try {
				sleep(1 * 60 * 1000);
			} catch (InterruptedException e) {
				log.debug("Memory-based shib handle cache cleanup interrupted.");
			}
			while (true) {
				try {
					if (shutdown) {
						log.debug("Stopping Memory-based shib handle cache cleanup thread.");
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
								log.debug("Expiring an Attribute Query Handle from the memory cache.");
								handleEntries.remove(deleteIterator.next());
							}
						}
					}
					sleep(1 * 60 * 1000);
				} catch (InterruptedException e) {
					log.debug("Memory-based shib handle cache cleanup interrupted.");
				}
			}
		}
	}

}