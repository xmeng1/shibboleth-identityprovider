package edu.internet2.middleware.shibboleth.wayf;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Implementaton of the <code>WayfCache</code> interface that does no cacheing of 
 * user selections.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class NullWayfCache implements WayfCache {

	/**
	 * @see WayfCache#addHsToCache(HttpServletRequest)
	 */
	public void addHsToCache(String handleService, HttpServletRequest req, HttpServletResponse res) {
		//don't do anything
	}

	/**
	 * @see WayfCache#deleteHsFromCache(HttpServletRequest)
	 */
	public void deleteHsFromCache(HttpServletRequest req, HttpServletResponse res) {
		//don't do anything
	}

	/**
	 * @see WayfCache#getCachedHS(HttpServletRequest)
	 */
	public String getCachedHS(HttpServletRequest req) {
		return null;
	}

	/**
	 * @see WayfCache#hasCachedHS(HttpServletRequest)
	 */
	public boolean hasCachedHS(HttpServletRequest req) {
		return false;
	}

}