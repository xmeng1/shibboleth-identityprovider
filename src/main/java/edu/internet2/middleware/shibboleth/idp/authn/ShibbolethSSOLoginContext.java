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

package edu.internet2.middleware.shibboleth.idp.authn;

/** Shibboleth SSO aware extension to {@link LoginContext}. */
public class ShibbolethSSOLoginContext extends LoginContext {

    /** Serial version UID. */
    private static final long serialVersionUID = -8388394528549536613L;

    /** Service provider assertion consumer service URL. */
    private String spAssertionConsumerService;

    /** Service provider target URL. */
    private String spTarget;

    /** Constructor. */
    public ShibbolethSSOLoginContext() {
        super(false, false);
    }

    /**
     * Gets the service provider assertion consumer service URL.
     * 
     * @return service provider assertion consumer service URL
     */
    public synchronized String getSpAssertionConsumerService() {
        return spAssertionConsumerService;
    }

    /**
     * Sets the service provider assertion consumer service URL.
     * 
     * @param url service provider assertion consumer service URL
     */
    public synchronized void setSpAssertionConsumerService(String url) {
        spAssertionConsumerService = url;
    }

    /**
     * Gets the service provider target URL.
     * 
     * @return service provider target URL
     */
    public synchronized String getSpTarget() {
        return spTarget;
    }

    /**
     * Sets the service provider target URL.
     * 
     * @param url service provider target URL
     */
    public synchronized void setSpTarget(String url) {
        spTarget = url;
    }
}