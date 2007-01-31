/*
 * Copyright [2006] [University Corporation for Advanced Internet Development, Inc.]
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

package edu.internet2.middleware.shibboleth.idp.authn;


import bsh.This;
import java.util.Map;
import javolution.util.FastMap;

import org.opensaml.saml2.core.RequestedAuthnContext;

/**
 * Login context created by a profile handler and interpreted
 * by the authentication package.
 * 
 * Two properties are tracked by default:
 * 
 * <code>forceAuth</code> - Should user authentiation be forced.
 * <code>passiveAuth</code> - Should user authentication not control the UI.
 * 
 * A Map&lt;String, Object&gt; is provided to store other properties.
 * Alternatively, a profile handler may create a subclass of LoginContext with
 * extra fields.
 */
public class Saml2LoginContext extends LoginContext {
    
    /** The {@link RequestedAuthnContext} */
    private RequestedAuthnContext ctx;
    
    
    /** Creates a new instance of LoginContext */
    public Saml2LoginContext() {
    }
    
    
    /**
     * Creates a new instance of LoginContext
     *
     * @param forceAuth if the authentication manager must reauth the user.
     * @param passiveAuth if the authentication manager must not interact with the users UI. 
     * @param ctx The requested login context.
     */
    public Saml2LoginContext(boolean forceAuth, boolean passiveAuth, final RequestedAuthnContext ctx) {
        
	super(forceAuth, passiveAuth);
	
	this.ctx = ctx;
    }    
    
    
    /**
     * Set the requested authentication context.
     *
     * @param ctx The requested authN context.
     */
    public void setRequestedAuthnContext(RequestedAuthnContext ctx) {
	this.ctx = ctx;
    }
    
    
    /**
     * Returns the requested authentication context.
     *
     * @return the RequestedAuthnContext, or <code>null</code> if none was set.
     */
    public RequestedAuthnContext getRequestedAuthnContext() {
	return this.ctx;
    }
    
 
}
