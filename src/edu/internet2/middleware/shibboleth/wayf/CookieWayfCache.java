package edu.internet2.middleware.shibboleth.wayf;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Implementation of <code>WayfCache</code> that uses Http Cookies to cache
 * user selections.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */
public class CookieWayfCache extends WayfCacheBase implements WayfCache {

	/**
	 * @see WayfCache#addHsToCache(HttpServletRequest)
	 */
	public void addHsToCache(
		String handleService,
		HttpServletRequest req,
		HttpServletResponse res) {
		Cookie cacheCookie = new Cookie("selectedHandleService", handleService);
		cacheCookie.setComment(
			"Used to cache selection of a user's Handle Service");

		//Should probably get this stuff from config
		/**     
		 cacheCookie.setMaxAge();
		 cacheCookie.setDomain();
		 **/
		res.addCookie(cacheCookie);
	}

	/**
	 * @see WayfCache#deleteHsFromCache(HttpServletRequest)
	 */
	public void deleteHsFromCache(
		HttpServletRequest req,
		HttpServletResponse res) {

		Cookie[] cookies = req.getCookies();
		for (int i = 0; i < cookies.length; i++) {
			if (cookies[i].getName().equals("selectedHandleService")) {
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
				if (cookies[i].getName().equals("selectedHandleService")) {
					return cookies[i].getValue();
				}
			}
		}
		return null;
	}

}