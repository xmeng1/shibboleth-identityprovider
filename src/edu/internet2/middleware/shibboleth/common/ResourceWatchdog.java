/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the
 * above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution, if any, must include the following acknowledgment: "This product includes
 * software developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu>Internet2
 * Project. Alternately, this acknowledegement may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear. Neither the name of Shibboleth nor the names of its contributors, nor Internet2,
 * nor the University Corporation for Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote
 * products derived from this software without specific prior written permission. For written permission, please
 * contact shibboleth@shibboleth.org Products derived from this software may not be called Shibboleth, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor may Shibboleth appear in their name,
 * without prior written permission of the University Corporation for Advanced Internet Development. THIS SOFTWARE IS
 * PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND
 * NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS
 * WITH LICENSEE. IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY CORPORATION FOR ADVANCED
 * INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.common;

import java.io.IOException;
import java.net.URLConnection;

import org.apache.log4j.Logger;

/**
 * Watchdog thread that polls resources at a specified interval and takes actions as prescribed by implementors.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public abstract class ResourceWatchdog extends Thread {

	private static Logger		log					= Logger.getLogger(ResourceWatchdog.class.getName());

	final static public long	DEFAULT_DELAY		= 60000;
	private long				delay				= DEFAULT_DELAY;
	protected ShibResource		resource;

	private long				lastModified		= 0;
	protected boolean			interrupted			= false;
	protected long				retries				= 0;
	protected long				maxRetries;
	final static public long	DEFAULT_MAX_RETRIES	= 10;

	protected ResourceWatchdog(ShibResource resource) {
		this.resource = resource;
		setDaemon(true);
		setDelay(DEFAULT_DELAY);
		if (getPriority() > Thread.MIN_PRIORITY) {
			setPriority(getPriority() - 1);
		}
		this.maxRetries = DEFAULT_MAX_RETRIES;
		lastModified = System.currentTimeMillis();
	}

	/**
	 * @param delay
	 *            the delay to observe between each check of the file changes.
	 * @param maxRetries
	 *            the maximum number of times to retry loading after the resource becomes unreachable or 0 for no
	 *            maximum
	 */
	protected ResourceWatchdog(ShibResource resource, long delay, long maxRetries) {
		this(resource, delay);
		this.maxRetries = maxRetries;
	}

	protected ResourceWatchdog(ShibResource resource, long delay) {
		this(resource);
		if (delay > 5000) {
			setDelay(delay);
			return;
		}
		try {
			log.warn("You have set the reload delay on resource (" + resource.getURL().toString() + ") to (" + delay
					+ ") seconds, which will probably cause perfomance problems.  Running with default reload "
					+ "time of (" + DEFAULT_DELAY + ") seconds...");
		} catch (IOException e) {
			log.warn("You have set the reload delay on a resource to (" + delay
					+ ") seconds, which will probably cause perfomance problems.  Running with default reload "
					+ "time of (" + DEFAULT_DELAY + ") seconds...");
		} finally {
			setDelay(DEFAULT_DELAY);
		}
	}

	/**
	 * Set the delay to observe between each check of the file changes.
	 */
	public void setDelay(long delay) {
		this.delay = delay;
	}

	/**
	 * This method is called when the Watchdog detects a change in the resource.
	 * 
	 * @throws WatchdogException
	 *             if it cannot perform the intended operation
	 */
	abstract protected void doOnChange() throws ResourceWatchdogExecutionException;

	protected void checkAndRun() {

		try {
			URLConnection connection = resource.getURL().openConnection();
			connection.connect();

			log.debug("Checking for updates to resource (" + resource.getURL().toString() + ")");

			long newLastModified = connection.getLastModified();

			if (newLastModified < 1) {
				interrupted = true;
				log.error("Resource (" + resource.getURL().toString() + ") does not provide modification dates.  "
						+ "Resource cannot be reloaded.");
				return;
			}

			if (newLastModified > lastModified) {
				log.debug("Previous Last Modified: " + lastModified + " New Last Modified: " + newLastModified);
				log.info("Found update for resource (" + resource.getURL().toString() + ")");
				lastModified = newLastModified;
				doOnChange();
				retries = 0;

			}

		} catch (Exception e) {
			try {
				if (maxRetries == 0 || retries < maxRetries) {
					log.error("Resource (" + resource.getURL().toString() + ") could not be loaded.  "
							+ "Will retry later.");
					retries++;
					return;

				} else {
					log.error("Unsuccessfully attempted to load resource (" + resource.getURL().toString()
							+ ") too many times.  " + "Resource cannot be reloaded.");
					interrupted = true;
					return;
				}
			} catch (IOException ioe) {
				log.error("Unsuccessfully attempted to load a resource too many times.  "
						+ "Resource cannot be reloaded.");
				interrupted = true;
				return;
			}
		}

	}

	public void run() {
		while (!interrupted) {
			try {
				Thread.sleep(delay);
			} catch (InterruptedException e) {
				// not applicable
			}
			checkAndRun();
		}
	}

}
