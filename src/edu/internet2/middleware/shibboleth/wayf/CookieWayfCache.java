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

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Implementation of <code>WayfCache</code> that uses Http Cookies to cache user selections.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */
public class CookieWayfCache extends WayfCacheBase implements WayfCache {

	private int expiration;
	private String domain;

	/**
	 * Constructs a <code>CookieWayfCache</code>
	 * 
	 * @param expiration
	 *            Cache validity period in seconds
	 * @param domain
	 *            Domain to which the cookie will be released
	 */
	public CookieWayfCache(int expiration, String domain) {

		this.expiration = expiration;
		if (domain != null && domain != "") {
			this.domain = domain;
		}
	}

	/**
	 * @see WayfCache#addHsToCache(HttpServletRequest)
	 */
	public void addHsToCache(String handleService, HttpServletRequest req, HttpServletResponse res) {

		Cookie cacheCookie = new Cookie("edu.internet2.middleware.shibboleth.wayf.selectedHandleService", handleService);
		configureCookie(cacheCookie);
		res.addCookie(cacheCookie);
	}

	/**
	 * @see WayfCache#deleteHsFromCache(HttpServletRequest)
	 */
	public void deleteHsFromCache(HttpServletRequest req, HttpServletResponse res) {

		Cookie[] cookies = req.getCookies();
		if (cookies == null) { return; }
		for (int i = 0; i < cookies.length; i++) {
			if (cookies[i].getName().equals("edu.internet2.middleware.shibboleth.wayf.selectedHandleService")) {
				configureCookie(cookies[i]);
				cookies[i].setMaxAge(0);
				res.addCookie(cookies[i]);
			}
		}
	}

	/**
	 * @see WayfCache#getCachedHS(HttpServletRequest)
	 */
	public String getCachedHS(HttpServletRequest req) {

		Cookie[] cookies = req.getCookies();
		if (cookies != null) {
			for (int i = 0; i < cookies.length; i++) {
				if (cookies[i].getName().equals("edu.internet2.middleware.shibboleth.wayf.selectedHandleService")) { return cookies[i]
						.getValue(); }
			}
		}
		return null;
	}

	private void configureCookie(Cookie cookie) {

		cookie.setComment("Used to cache selection of a user's Shibboleth Handle Service");
		cookie.setPath("/");

		if (expiration > 0) {
			cookie.setMaxAge(expiration);
		}
		if (domain != null && domain != "") {
			cookie.setDomain(domain);
		}
	}

}