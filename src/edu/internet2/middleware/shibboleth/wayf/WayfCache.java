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

/**
 * Defines a method for cacheing user selections regarding which shibboleth Handle Service should be used.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public interface WayfCache {

	/**
	 * Add the specified Shibboleth Handle Service to the cache.
	 */
	public void addHsToCache(String handleService, HttpServletRequest req, HttpServletResponse res);

	/**
	 * Delete the Shibboleth Handle Service assoctiated with the current requester from the cache.
	 */
	public void deleteHsFromCache(HttpServletRequest req, HttpServletResponse res);

	/**
	 * Returns boolean indicator as to whether the current requester has a Handle Service entry in the cache.
	 */
	public boolean hasCachedHS(HttpServletRequest req);

	/**
	 * Retrieves the Handle Service associated with the current requester. Returns null if there is none currently
	 * associated.
	 */
	public String getCachedHS(HttpServletRequest req);

}