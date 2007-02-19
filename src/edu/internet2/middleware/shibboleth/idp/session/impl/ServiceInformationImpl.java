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

import edu.internet2.middleware.shibboleth.idp.session.AuthenticationMethodInformation;
import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.NameID;

/**
 * Information about a service a user has logged in to.
 */
public class ServiceInformationImpl implements ServiceInformation {

    /** Entity ID of the service. */
    private String entityID;

    /** Instant the user was authenticated to the service. */
    private DateTime authenticationInstant;

    /** Authentication method used to authenticate the user to the service. */
    private AuthenticationMethodInformation methodInfo;

    /** Name ID provided to the service. */
    private NameID nameId;

    /**
     * Default constructor.
     * 
     * @param entityID The unique identifier for the service.
     * @param authenticationInstant The time the user authenticated to the service.
     * @param methodInfo The authentication method used to log into the service.
     * @param nameId The {@link NameID} used for the subject/user with this service.
     * 
     */
    public ServiceInformationImpl(String entityID, DateTime authenticationInstant, AuthenticationMethodInformation methodInfo,
            NameID nameId) {

        this.entityID = entityID;
        this.authenticationInstant = authenticationInstant;
        this.methodInfo = methodInfo;
        this.nameId = nameId;
    }

    /**
     * Cloning constructor.
     * 
     * @param serviceInfo The ServiceInformation instance to duplicate.
     */
    public ServiceInformationImpl(final ServiceInformation serviceInfo) {

        if (serviceInfo == null) {
            return;
        }

        this.entityID = serviceInfo.getEntityID();
        this.authenticationInstant = serviceInfo.getAuthenticationInstant();
        this.methodInfo = serviceInfo.getAuthenticationMethod();
        this.nameId = serviceInfo.getSubjectNameID();
    }

    /** {@inheritDoc} */
    public String getEntityID() {
        return entityID;
    }

    /** {@inheritDoc} */
    public DateTime getAuthenticationInstant() {
        return authenticationInstant;
    }

    /** {@inheritDoc} */
    public AuthenticationMethodInformation getAuthenticationMethod() {
        return methodInfo;
    }

    /** {@inheritDoc} */
    public NameID getSubjectNameID() {
        return nameId;
    }

    /** {@inheritDoc} */
    public boolean equals(Object obj) {
        if (!(obj instanceof ServiceInformation)) {
            return false;
        }

        ServiceInformation si = (ServiceInformation) obj;
        if (this.getEntityID().equals(si.getEntityID())
                && this.getAuthenticationInstant().equals(si.getAuthenticationInstant())
                && this.getSubjectNameID().equals(si.getSubjectNameID())) {

            return true;
        }
        
        return false;
    }
}