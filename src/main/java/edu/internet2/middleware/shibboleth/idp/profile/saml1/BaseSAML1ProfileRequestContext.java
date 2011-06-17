/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.idp.profile.saml1;

import org.opensaml.common.SAMLObject;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml1.core.ResponseAbstractType;
import org.opensaml.saml1.core.Status;

import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml1.AbstractSAML1ProfileConfiguration;

/**
 * Contextual object used to accumlate information as profile requests are being processed.
 * 
 * @param <RequestType> type of SAML 1 request
 * @param <ResponseType> type of SAML 1 response
 * @param <ProfileConfigurationType> configuration type for this profile
 */
public abstract class BaseSAML1ProfileRequestContext<RequestType extends SAMLObject, ResponseType extends ResponseAbstractType, ProfileConfigurationType extends AbstractSAML1ProfileConfiguration>
        extends BaseSAMLProfileRequestContext<RequestType, ResponseType, NameIdentifier, ProfileConfigurationType> {

    /** The request failure status. */
    private Status failureStatus;

    /**
     * Gets the status reflecting a request failure.
     * 
     * @return status reflecting a request failure
     */
    public Status getFailureStatus() {
        return failureStatus;
    }

    /**
     * Sets the status reflecting a request failure.
     * 
     * @param status status reflecting a request failure
     */
    public void setFailureStatus(Status status) {
        failureStatus = status;
    }
}