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

package edu.internet2.middleware.shibboleth.idp.session.impl;

import java.util.List;

import javolution.util.FastList;

import edu.internet2.middleware.shibboleth.idp.session.AuthenticationMethodInformation;
import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;
import edu.internet2.middleware.shibboleth.idp.session.Session;

// implementation note: 
// pay attention to package names in this file!
//
// this class is shib.idp.session.impl.SessionImpl. It implements the shib.idp.session.Session
// interface. that interface, in turn, extends shib.common.session.Session, which is implemented
// in shib.common.session.impl.SessionImpl.


/**
 * Session information for user logged into the IdP.
 */
public class SessionImpl
	extends edu.internet2.middleware.shibboleth.common.session.impl.SessionImpl
	implements Session {
    
    /** The list of methods used to authentictate the user */
    private List<AuthenticationMethodInformation> authnMethods =
	    new FastList<AuthenticationMethodInformation>();
    
    /** The list of services to which the user has logged in */
    private List<ServiceInformation> servicesInformation =
	    new FastList<ServiceInformation>();

    
    /**
     * Default constructor.
     * 
     * @param principalID The principal ID of the user
     */
    public SessionImpl(String principalID) {
    	
    	super(principalID);
    }
    
    
    /** {@inheritDoc} */
    public List<AuthenticationMethodInformation> getAuthenticationMethods() {
    
	// XXX : This is suspect. One should not return
	// a reference to a private mutable object. The Session
	// interface should have methods for adding and removing
	// AuthenticationMethodInformation and ServicesInformation
	// entries. Further, the Session interface assumes that 
	// the implementation will return a thread-safe List. Not
	// all List implementations are thread-safe.
	    
	return this.authnMethods;
    }


    /** {@inheritDoc} */
    public List<ServiceInformation> getServicesInformation() {
	
	// XXX: warning: Potentially dangerous. see above note.
	
	return this.servicesInformation;
    }
    
}
