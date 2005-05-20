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

/**
 * Runtime configuration bundle that is passed to a <code>WayfCacheFactory</code>.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */
public class WayfCacheOptions {

	private int expiration;
	private String domain;

	/**
	 * Returns the domain.
	 * 
	 * @return String
	 */
	public String getDomain() {

		return domain;
	}

	/**
	 * Returns the expiration.
	 * 
	 * @return int
	 */
	public int getExpiration() {

		return expiration;
	}

	/**
	 * Sets the domain.
	 * 
	 * @param domain
	 *            The domain to set
	 */
	public void setDomain(String domain) {

		this.domain = domain;
	}

	/**
	 * Sets the expiration.
	 * 
	 * @param expiration
	 *            The expiration to set
	 */
	public void setExpiration(int expiration) {

		this.expiration = expiration;
	}

}
