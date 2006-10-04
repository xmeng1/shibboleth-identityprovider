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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;

import edu.internet2.middleware.shibboleth.common.Cache;
import edu.internet2.middleware.shibboleth.common.CacheException;

/**
 * <code>Cache</code> implementation that uses Servlet API sessions to cache data. This implementation will reap
 * expired entries as they are accessed, but primarily relies on the servlet container and the web browser to handle
 * invalidation of cached values.
 * 
 * @author Walter Hoehn
 */
public class ServletSessionCache extends BaseCache implements Cache {

	private static Logger log = Logger.getLogger(ServletSessionCache.class.getName());
	private HttpSession session;

	ServletSessionCache(String name, HttpServletRequest request) {

		super(name, Cache.CacheType.CLIENT_SERVER_SHARED);

		if (request == null) { throw new IllegalArgumentException(
				"Servlet request is  required for construction of BaseCache."); }

		this.session = request.getSession();
	}

	private String getInternalKeyName(String externalKey) {

		return this.getClass().getName() + "::" + getName() + "::" + externalKey;
	}

	public boolean contains(String key) {

		// Lookup object
		Object object = session.getAttribute(getInternalKeyName(key));
		if (object == null || !(object instanceof CacheEntry)) { return false; }

		// Clean cache if it is expired
		if (((CacheEntry) object).isExpired()) {
			log.debug("Found expired object.  Deleting...");
			session.removeAttribute(getInternalKeyName(key));
			return false;
		}

		// OK, we have it
		return true;
	}

	public String retrieve(String key) {

		// Lookup object
		Object object = session.getAttribute(getInternalKeyName(key));
		if (object == null || !(object instanceof CacheEntry)) { return null; }

		// Clean cache if it is expired
		if (((CacheEntry) object).isExpired()) {
			log.debug("Found expired object.  Deleting...");
			session.removeAttribute(getInternalKeyName(key));
			return null;
		}

		// OK, we have it
		return ((CacheEntry) object).value;
	}

	public void store(String key, String value, long duration) {

		session.setAttribute(getInternalKeyName(key), new CacheEntry(value, duration));
	}

	public void remove(String key) throws CacheException {

		session.removeAttribute(getInternalKeyName(key));
	}

}
