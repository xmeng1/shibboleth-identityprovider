package edu.internet2.middleware.shibboleth.wayf;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Implementation of <code>WayfCache</code> that uses Java Servlet Sessions to cache
 * user selections.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class SessionWayfCache extends WayfCacheBase implements WayfCache {

	/**
	 * @see WayfCache#addHsToCache(HttpServletRequest)
	 */
	public void addHsToCache(
		String handleService,
		HttpServletRequest req,
		HttpServletResponse res) {
			
		HttpSession session = req.getSession(true);
		session.setMaxInactiveInterval(7200);
		session.setAttribute("selectedHandleService", handleService);
	}

	/**
	 * @see WayfCache#deleteHsFromCache(HttpServletRequest)
	 */
	public void deleteHsFromCache(
		HttpServletRequest req,
		HttpServletResponse res) {
			
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
		if (session == null) {
			return null;
		}
		return (String) session.getAttribute("selectedHandleService");
	}
}