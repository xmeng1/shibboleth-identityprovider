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

package edu.internet2.middleware.shibboleth.common;

/**
 * Defines an IdP-wide caching mechanism.
 * 
 * @author Walter Hoehn
 */
public interface Cache {

	public enum CacheType {
		CLIENT_SIDE, SERVER_SIDE, CLIENT_SERVER_SHARED
	}

	/**
	 * Returns the identifier for the cache. This will commonly be a string name for the subsytem that is accessing the
	 * cache. Effectively acts as a namespace for the caching mechanisms.
	 */
	public String getName();

	/**
	 * Returns an indication of how the cache stores its data. Subsystems may enforce storage requirements on caches via
	 * this mechanism.
	 */
	public CacheType getCacheType();

	/**
	 * Causes the cache to return a value associated with a given key.
	 * 
	 * @throws CacheException
	 *             if an error was encountered while reading the cache
	 */
	public String retrieve(String key) throws CacheException;

	/**
	 * Causes the cache to remove a value associated with a given key.
	 * 
	 * @throws CacheException
	 *             if an error was encountered while removing the value from the cache
	 */
	public void remove(String key) throws CacheException;

	/**
	 * Boolean indication of whether or not the cache contains a value tied to a specified key.
	 * 
	 * @throws CacheException
	 *             if an error was encountered while reading the cache
	 */
	public boolean contains(String key) throws CacheException;

	/**
	 * Causes the cache to associate a value with a given key for a specified number of seconds.
	 * 
	 * @throws CacheException
	 *             if the value could not be written to the cache
	 */
	public void store(String key, String value, long duration) throws CacheException;
}
