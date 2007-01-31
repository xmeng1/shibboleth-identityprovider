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

import org.joda.time.DateTime;

import edu.internet2.middleware.shibboleth.idp.session.AuthenticationMethodInformation;


/**
 * Information about an authentication method employed by a user.
 */
public class AuthenticationMethodInformationImpl implements AuthenticationMethodInformation {
    
    /** The authentication method (a URI) */
    private String authenticationMethod;
    
    /** The timestamp at which authentication occurred */
    private DateTime authenticationInstant;
    
    /** The lifetime of the authentication method */
    private long authenticationDuration;
    
    
    /**
     * Default constructor
     *
     * @param authenticationMethod The unique identifier for the authentication method.
     * @param authenticationInstant The time the user authenticated with this member.
     * @param authenticationDuration The duration of this authentication method.
     */
    public AuthenticationMethodInformationImpl(final String authenticationMethod,
	    final DateTime authenticationInstant, long authenticationDuration) {
	
	if (authenticationMethod == null || authenticationInstant == null
		|| authenticationDuration < 0) {
	    return;
	}
	
	this.authenticationMethod = authenticationMethod;
	this.authenticationInstant = authenticationInstant;
	this.authenticationDuration = authenticationDuration;
    }
    
    
    /**
     * "Cloning" constructor.
     *
     * @param methodInfo The {@link AuthenticationMethodInfo} to duplicate.
     */
    public AuthenticationMethodInformationImpl(final AuthenticationMethodInformation methodInfo) {
	
	if (methodInfo == null) {
	    return;
	}
	
	this.authenticationMethod = methodInfo.getAuthenticationMethod();
	this.authenticationInstant = methodInfo.getAuthenticationInstant();
	this.authenticationDuration = methodInfo.getAuthenticationDuration();
    }
    
    
    /** {@inheritDoc} */
    public String getAuthenticationMethod() {
	return this.authenticationMethod;
    }
    
    
    /** {@inheritDoc} */
    public DateTime getAuthenticationInstant() {
	return this.authenticationInstant;
    }
    
    
    /** {@inheritDoc} */
    public long getAuthenticationDuration() {
	return this.authenticationDuration;
    }
    
    
    /** {@inheritDoc} */
    public boolean equals(Object obj) {
	
	if (!(obj instanceof AuthenticationMethodInformation)) {
	    return false;
	}
	
	AuthenticationMethodInformation amInfo = (AuthenticationMethodInformation)obj;
	
	if (this.getAuthenticationMethod().equals(amInfo.getAuthenticationMethod())
	    && this.getAuthenticationInstant().equals(amInfo.getAuthenticationInstant())
	    && this.getAuthenticationDuration() == amInfo.getAuthenticationDuration()) {
	    
	    return true;
	} else {
	    return false;
	}
    }
}
