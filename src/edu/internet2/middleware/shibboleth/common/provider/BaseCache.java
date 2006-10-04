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

package edu.internet2.middleware.shibboleth.common.provider;

import java.util.Date;

import edu.internet2.middleware.shibboleth.common.Cache;

/**
 * Functionality common to all implementations of <code>Cache</code>.
 * 
 * @author Walter Hoehn
 */
public abstract class BaseCache implements Cache {

	private String name;
	private CacheType cacheType;

	protected BaseCache(String name, CacheType type) {

		if (name == null || type == null) { throw new IllegalArgumentException(
				"Name and type are required for construction of BaseCache."); }

		this.name = name;
		this.cacheType = type;
	}

	public CacheType getCacheType() {

		return cacheType;
	}

	public String getName() {

		return name;
	}

	protected class CacheEntry {

		protected Date expiration;
		protected String value;

		protected CacheEntry(String value, long duration) {

			this.value = value;
			expiration = new Date(System.currentTimeMillis() + (duration * 1000));
		}

		protected CacheEntry(String value, Date expireAt) {

			this.value = value;
			this.expiration = expireAt;
		}

		protected boolean isExpired() {

			return (new Date().after(expiration));
		}
	}
}
