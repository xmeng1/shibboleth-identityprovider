/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
 * provided with the distribution, if any, must include the following acknowledgment: "This product includes software
 * developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu> Internet2 Project.
 * Alternately, this acknowledegement may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear. Neither the name of Shibboleth nor the names of its contributors, nor Internet2, nor
 * the University Corporation for Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote
 * products derived from this software without specific prior written permission. For written permission, please contact
 * shibboleth@shibboleth.org Products derived from this software may not be called Shibboleth, Internet2, UCAID, or the
 * University Corporation for Advanced Internet Development, nor may Shibboleth appear in their name, without prior
 * written permission of the University Corporation for Advanced Internet Development. THIS SOFTWARE IS PROVIDED BY THE
 * COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE
 * DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. IN NO
 * EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC.
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.artifact.provider;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import org.apache.log4j.Logger;
import org.opensaml.artifact.Artifact;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.artifact.ArtifactMapper;
import edu.internet2.middleware.shibboleth.artifact.ArtifactMapping;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;

/**
 * <code>ArtifactMapper</code> implementation that saves queryable artifacts in memory.
 * 
 * @author Walter Hoehn
 */
public class MemoryArtifactMapper extends BaseArtifactMapper implements ArtifactMapper {

	private MemoryArtifactCleaner cleaner = new MemoryArtifactCleaner();
	private static Logger log = Logger.getLogger(MemoryArtifactMapper.class.getName());
	private static Map mappings = Collections.synchronizedMap(new HashMap());

	public MemoryArtifactMapper() throws ShibbolethConfigurationException {

		super();
	}

	public MemoryArtifactMapper(Element config) throws ShibbolethConfigurationException {

		super(config);
	}

	public ArtifactMapping recoverAssertion(Artifact artifact) {

		ArtifactMapping mapping = (ArtifactMapping) mappings.get(artifact);
		mappings.remove(artifact);
		if (mapping == null || mapping.isExpired()) { return null; }
		return mapping;
	}

	public void addAssertionImpl(Artifact artifact, ArtifactMapping mapping) {

		mappings.put(artifact, mapping);
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

	private class MemoryArtifactCleaner extends Thread {

		private boolean shutdown = false;
		private Thread master;

		public MemoryArtifactCleaner() {

			super("edu.internet2.middleware.shibboleth.idp.provider.MemoryArtifactMapper..MemoryArtifactCleaner");
			this.master = Thread.currentThread();
			setDaemon(true);
			if (getPriority() > Thread.MIN_PRIORITY) {
				setPriority(getPriority() - 1);
			}
			log.debug("Starting memory-based artifact mapper cleanup thread.");
			start();
		}

		public void run() {

			try {
				sleep(60 * 1000); // one minute
			} catch (InterruptedException e) {
				log.debug("Memory-based artifact mapper cleanup interrupted.");
			}
			while (true) {
				try {
					if (!master.isAlive()) {
						shutdown = true;
						log.debug("Memory-based artifact mapper cleaner is orphaned.");
					}
					if (shutdown) {
						log.debug("Stopping Memory-based artifact mapper cleanup thread.");
						return;
					}
					log.debug("Memory cartifact mapper cleanup thread searching for stale entries.");
					Set needsDeleting = new HashSet();
					synchronized (mappings) {
						Iterator iterator = mappings.entrySet().iterator();
						while (iterator.hasNext()) {
							Entry entry = (Entry) iterator.next();
							ArtifactMapping mapping = (ArtifactMapping) entry.getValue();
							if (mapping.isExpired()) {
								needsDeleting.add(entry.getKey());
							}
						}
						// release the lock to be friendly
						Iterator deleteIterator = needsDeleting.iterator();
						while (deleteIterator.hasNext()) {
							synchronized (mappings) {
								log.debug("Expiring an Artifact from the memory cache.");
								mappings.remove(deleteIterator.next());
							}
						}
					}
					sleep(60 * 1000); // one minute
				} catch (InterruptedException e) {
					log.debug("Memory-based artifact mapper cleanup interrupted.");
				}
			}
		}
	}

}