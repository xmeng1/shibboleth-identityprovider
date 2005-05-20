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
 * ServiceProviderContext.java
 * 
 * There is one ServiceProviderContext per Service Provider.
 * Other objects and collections of objects are referenced through it.
 * 
 * An object of type ServiceProviderContext must be created and
 * shared among the Shibboleth classes in the same Service Provider.
 * The default implimentation is for the object to be created during
 * the static initialization of the class and accessed through the
 * static getInstance() factory method.
 * 
 * Any change to this strategy can be propagated to all other classes
 * just by changing the getInstance() method implementation to use 
 * a different factory or lookup service.
 */
package edu.internet2.middleware.shibboleth.serviceprovider;

import org.opensaml.NoSuchProviderException;
import org.opensaml.ReplayCache;
import org.opensaml.ReplayCacheFactory;

/**
 * Unique object through which all Service Provider objects and collections
 * are found. Obtain a reference to this object by calling the static
 * getInstance() method.
 * 
 * @author Howard Gilbert
 *
 */
public class ServiceProviderContext {
	
	/*
	 * This static object provides the default implimentation of the 
	 * ServiceProviderContext singleton object. However, the getInstance
	 * Factory actually determines the particular instance used.
	 * 
	 * Warning:
	 * 
	 * Some of the following fields may have an initialization
	 * expression as in "Foo x = new Foo()".
	 * The "Foo" class in turn may have a constructor or its own
	 * static and non-static initialization statements. If anywhere
	 * in this cascade of initialization triggered directly or 
	 * indirectly by creating this first new object of type
	 * ServiceProviderContext() there is some code that calls
	 * back to getServiceProviderContext() then it will get back
	 * a null from that call. This is because the SPContext
	 * variable is not filled in with a reference to the object 
	 * until it is constructed, and we are still in the middle of
	 * constructing it.  
	 */
	private static ServiceProviderContext targetContext = new ServiceProviderContext();
	
	/*
	 * The fatalErrors flag provides a global reference where Service Provider
	 * components can know that we are totally hosed and cannot proceed. When
	 * set, this tells all servlets right up front to generate error messages
	 * and apologize.
	 */
	private boolean fatalErrors = false; 
	
	
	
	/**
	 * <p>Static Factory method to return the ServiceProviderContext.
	 * </p><p>
	 * The default implmementation is to use a static field. 
	 * However, in other environments you may wish to replace this
	 * with an object managed by J2EE or by Spring. If so, create
	 * the object someplace else and change this factory to locate
	 * it with LDAP, an external context, Spring, or whatever.
	 * </p>
	 * @return Returns the ServiceProviderContext object.
	 */
	public static ServiceProviderContext getInstance() {
		return targetContext;
	}
	
	/**
	 * The ServiceProviderConfig object holds all information from
	 * the configuration file and the other sources of information
	 * and metadata to which it refers.
	 */
	private ServiceProviderConfig serviceProviderConfig = null;
	
	
	
	/*
	 * <p>Manager for the collection (and Cache) of Session Objects
	 * </p><p>
	 * All access to and creation/deletion of Sessions occurs through
	 * this object. This could be a wiring point later if someone
	 * wanted to load and configure the Session Manager in Spring.
	 */
	private SessionManager sessionManager = null;

	private ReplayCache replayCache = null;
	
	private ThreadLocal requestContext = new ThreadLocal();
		public void setRequestContext(RequestTracker trk) {
		    requestContext.set(trk);
		}
		public RequestTracker getRequestContext() {
		    return (RequestTracker) requestContext.get();
		}

	/**
	 * Constructor currently made private to force use of getInstance()
	 */
	private ServiceProviderContext() {
	}
	
	
	
	// property accessor methods

	public synchronized SessionManager getSessionManager() {
	    // deferred allocation, since sessionManger needs a reference
	    // back to context.
	    if (sessionManager==null)
		    sessionManager = new SessionManager();
		return sessionManager;
	}

    // TODO: Make this pluggable / configurable
    public synchronized ReplayCache getReplayCache() {
        if (replayCache == null) {
            try {
                replayCache = ReplayCacheFactory.getInstance();
            }
            catch (NoSuchProviderException e) {
            }
        }
        return replayCache;
    }
    
	public ServiceProviderConfig getServiceProviderConfig() {
		return serviceProviderConfig;
	}
	public void setServiceProviderConfig(
			ServiceProviderConfig serviceProviderConfig) {
		this.serviceProviderConfig = serviceProviderConfig;
	}
	public boolean isFatalErrors() {
		return fatalErrors;
	}
	public void setFatalErrors(boolean fatalErrors) {
		this.fatalErrors = fatalErrors;
	}
	
}
