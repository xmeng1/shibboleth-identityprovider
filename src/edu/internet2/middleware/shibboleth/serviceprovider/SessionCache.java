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

/*
 * SessionCache.java
 * 
 * A Session Cache implementation saves the content of all current
 * Session objects to some form of disk storage. This has two 
 * advantages:
 * 
 * It allows the Sessions (and their saved Assertions) to be 
 * restored after the host computer, Web server, or /shibboleth
 * context are recycled. 
 * 
 * It allows the cookies, handles, and assertions to be shared
 * (provided the cache is shared) between multiple hosts in a
 * load balancing configuration.
 * 
 * Exactly where you cache Sessions is up to you. A few obvious
 * possible implementations are:
 * 
 * Write the Session fields (Strings and XML) to columns of a 
 * database table using JDBC. The primary key of the table is
 * the sessionId.
 * 
 * Serialize the Session object to a file in a cache directory.
 * The name of the file would be {sessionId}.xml
 * 
 * Use a persistance framework or Object Relational mapping
 * system (Hibernate is popular) to persist the objects.
 * 
 * Note: The Assertions in the Session extend DOM objects, so
 * they can be serialized to character strings and parsed on 
 * the way back if your store doesn't support XML columns natively.
 * 
 * Design point: There are two ways to handle a reboot.
 * 1) The Cache could return an iterator and the SessionManager could
 * run through all its entries storing them in the collection.
 * 2) The MemoryMananager can pass the collection to the Cache to
 * fill in from persistent storage.
 * This interface adopts the second approach, but that is just a
 * value judgement. 
 */
package edu.internet2.middleware.shibboleth.serviceprovider;

import java.util.Map;

/**
 * <p>An interface to be implemented by any Plug-In cache Session Cache.
 * </p><p>
 * To create a cache, write an implementation class for this interface
 * and call SessionMananger.setSessionCache(...) passing the cache 
 * implementation object. While the cache can be loaded as a Shibboleth
 * Service Provider plugin, it can also be loaded, configured, and attached
 * to the class using J2EE (web.xml) or other Framework (Spring, ...) services.
 * </p>
 * 
 * <p>Restriction: There can be only one.</p>
 * 
 * @author Howard Gilbert
 */
/**
 * @author Howard Gilbert
 */
public interface SessionCache {
	
	/**
	 * <p>Find a Session in the cache
	 * </p><p>
	 * This entry point is only meaningful if the cache is being
	 * used for load balancing. Then it finds Sessions created
	 * by another host in the cluster. In a single-host cache
	 * you can always return null because all Sessions will be
	 * in memory, and an id not found in memory will never be
	 * in the cache.</p>
	 * 
	 * @param sessionId Key string, typically the Cookie value
	 * @return Session object from cache
	 */
	public Session find(String sessionId);
	
	public void add(Session s);
	
	public void update(Session s);
	
	public void remove(Session s);
	
	/**
	 * Scan all Sessions in the cache and store them in
	 * the in memory collection. Typically called after
	 * a reboot to restore prior sessions.
	 * 
	 * @param sessions The in memory map to be loaded.
	 */
	public void reload(Map sessions);
	
	public void close();
	
}
