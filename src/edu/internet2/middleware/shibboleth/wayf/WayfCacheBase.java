package edu.internet2.middleware.shibboleth.wayf;

import javax.servlet.http.HttpServletRequest;

/**
 * @author Administrator
 *
 * To change this generated comment edit the template variable "typecomment":
 * Window>Preferences>Java>Templates.
 * To enable and disable the creation of type comments go to
 * Window>Preferences>Java>Code Generation.
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
