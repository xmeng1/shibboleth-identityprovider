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

package edu.internet2.middleware.shibboleth.wayf;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Implementation of <code>WayfCache</code> that uses Java Servlet Sessions to cache user selections.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class SessionWayfCache extends WayfCacheBase implements WayfCache {

	private int expiration;

	/**
	 * @param expiration
	 *            The time in seconds between requests at which point this cache entry will be invalidated.
	 */
	public SessionWayfCache(int expiration) {

		if (expiration == 0) {
			this.expiration = 7200;
		} else {
			this.expiration = expiration;
		}
	}

	/**
	 * @see WayfCache#addHsToCache(HttpServletRequest)
	 */
	public void addHsToCache(String handleService, HttpServletRequest req, HttpServletResponse res) {

		HttpSession session = req.getSession(true);
		session.setMaxInactiveInterval(expiration);
		session.setAttribute("selectedHandleService", handleService);
	}

	/**
	 * @see WayfCache#deleteHsFromCache(HttpServletRequest)
	 */
	public void deleteHsFromCache(HttpServletRequest req, HttpServletResponse res) {

		HttpSession session = req.getSession(false);
		if (session != null) {
			session.removeAttribute("selectedHandleService");
		}
	}

	/**
	 * @see WayfCache#getCachedHS(HttpServletRequest)
	 */
	public String getCachedHS(HttpServletRequest req) {

		HttpSession session = req.getSession(false);
		if (session == null) { return null; }
		return (String) session.getAttribute("selectedHandleService");
	}
}