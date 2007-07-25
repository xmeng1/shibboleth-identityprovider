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

import javax.security.auth.Subject;

import org.joda.time.DateTime;

import edu.internet2.middleware.shibboleth.idp.session.AuthenticationMethodInformation;

/**
 * Information about an authentication method employed by a user.
 */
public class AuthenticationMethodInformationImpl implements AuthenticationMethodInformation {

    /** Subject created by this authentication mechanism. */
    private Subject authenticationSubject;
    
    /** The authentication method (a URI). */
    private String authenticationMethod;

    /** The timestamp at which authentication occurred. */
    private DateTime authenticationInstant;

    /** The lifetime of the authentication method. */
    private long authenticationDuration;

    /** Time when this method expires. */
    private DateTime expirationInstant;

    /**
     * Default constructor.
     * 
     * @param method The unique identifier for the authentication method.
     * @param instant The time the user authenticated with this member.
     * @param duration The duration of this authentication method.
     */
    public AuthenticationMethodInformationImpl(String method, DateTime instant, long duration) {

        if (method == null || instant == null || duration < 0) {
            throw new IllegalArgumentException("Authentication method, instant, and duration may not be null");
        }

        authenticationMethod = method;
        authenticationInstant = instant;
        authenticationDuration = duration;
        expirationInstant = instant.plus(duration);
    }
    
    /**
     * Default constructor.
     * 
     * @param subject Subject created by the authentication method
     * @param method The unique identifier for the authentication method.
     * @param instant The time the user authenticated with this member.
     * @param duration The duration of this authentication method.
     */
    public AuthenticationMethodInformationImpl(Subject subject, String method, DateTime instant, long duration) {

        if (method == null || instant == null || duration < 0) {
            throw new IllegalArgumentException("Authentication method, instant, and duration may not be null");
        }

        authenticationSubject = subject;
        authenticationMethod = method;
        authenticationInstant = instant;
        authenticationDuration = duration;
        expirationInstant = instant.plus(duration);
    }
    
    /** {@inheritDoc} */
    public Subject getAuthenticationSubject() {
        return authenticationSubject;
    }

    /** {@inheritDoc} */
    public String getAuthenticationMethod() {
        return authenticationMethod;
    }

    /** {@inheritDoc} */
    public DateTime getAuthenticationInstant() {
        return authenticationInstant;
    }

    /** {@inheritDoc} */
    public long getAuthenticationDuration() {
        return authenticationDuration;
    }

    /** {@inheritDoc} */
    public boolean isExpired() {
        return expirationInstant.isBeforeNow();
    }
    
    /** {@inheritDoc} */
    public int hashCode() {
        return authenticationMethod.hashCode();
    }

    /** {@inheritDoc} */
    public boolean equals(Object obj) {
        if (!(obj instanceof AuthenticationMethodInformation)) {
            return false;
        }

        AuthenticationMethodInformation amInfo = (AuthenticationMethodInformation) obj;
        return authenticationMethod.equals(amInfo.getAuthenticationMethod());
    }
}