package edu.internet2.middleware.shibboleth.wayf;

import javax.servlet.http.HttpServletRequest;

/**
 * Shared implementation code for <code>WayfCache</code>.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */
public abstract class WayfCacheBase implements WayfCache {

	/**
	 * @see WayfCache#getCachedHS(HttpServletRequest)
	 */
	public boolean hasCachedHS(HttpServletRequest req) {
		if (getCachedHS(req) == null) {
			return false;
		} else {
			return true;
		}
	}

}