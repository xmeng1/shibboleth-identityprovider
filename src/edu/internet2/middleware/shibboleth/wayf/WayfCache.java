package edu.internet2.middleware.shibboleth.wayf;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Defines a method for cacheing user selections regarding which 
 * shibboleth Handle Service should be used.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public interface WayfCache {

	/**
	 * Add the specified Shibboleth Handle Service to the cache.
	 */
	public void addHsToCache(
		String handleService,
		HttpServletRequest req,
		HttpServletResponse res);

	/**
	 * Delete the Shibboleth Handle Service assoctiated with the current requester from the cache.
	 */
	public void deleteHsFromCache(
		HttpServletRequest req,
		HttpServletResponse res);

	/**
	 * Returns boolean indicator as to whether the current requester has a Handle Service entry 
	 * in the cache. 
	 */
	public boolean hasCachedHS(HttpServletRequest req);

	/**
	 * Retrieves the Handle Service associated with the current requester.  Returns null
	 * if there is none currently associated.
	 */
	public String getCachedHS(HttpServletRequest req);

}