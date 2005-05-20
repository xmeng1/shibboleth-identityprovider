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
 * Implementaton of the <code>WayfCache</code> interface that does no cacheing of user selections.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class NullWayfCache implements WayfCache {

	/**
	 * @see WayfCache#addHsToCache(HttpServletRequest)
	 */
	public void addHsToCache(String handleService, HttpServletRequest req, HttpServletResponse res) {

	// don't do anything
	}

	/**
	 * @see WayfCache#deleteHsFromCache(HttpServletRequest)
	 */
	public void deleteHsFromCache(HttpServletRequest req, HttpServletResponse res) {

	// don't do anything
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