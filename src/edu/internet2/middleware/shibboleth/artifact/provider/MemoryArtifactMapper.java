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