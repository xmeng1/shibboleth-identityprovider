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

import java.util.List;

import org.opensaml.common.binding.BasicEndpointSelector;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An endpoint selector that may optionally take a SP-provided assertion consumer service URL, validate it against
 * metadata, and return an endpoint based on it. If no URL is provided the {@link BasicEndpointSelector} selection is
 * used.
 */
public class ShibbolethSSOEndpointSelector extends BasicEndpointSelector {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(ShibbolethSSOEndpointSelector.class);

    /** Assertion consumer service URL provided by SP. */
    private String spAssertionConsumerService;

    /**
     * Gets the assertion consumer service URL provided by SP.
     * 
     * @return assertion consumer service URL provided by SP
     */
    public String getSpAssertionConsumerService() {
        return spAssertionConsumerService;
    }

    /**
     * Sets the assertion consumer service URL provided by SP.
     * 
     * @param acs assertion consumer service URL provided by SP
     */
    public void setSpAssertionConsumerService(String acs) {
        spAssertionConsumerService = DatatypeHelper.safeTrimOrNullString(acs);
    }

    /** {@inheritDoc} */
    public Endpoint selectEndpoint() {
        if (getEntityRoleMetadata() == null) {
            log.debug("Unable to select endpoint, no entity role metadata available.");
            return null;
        }

        if (spAssertionConsumerService != null) {
            return selectEndpointByACS();
        } else {
            return super.selectEndpoint();
        }
    }

    /**
     * Selects the endpoint, from metadata, corresponding to the SP-provdided ACS URL.
     * 
     * @return endpoint corresponding to the SP-provdided ACS URL
     */
    protected Endpoint selectEndpointByACS() {
        log.debug("Selecting endpoint from metadata corresponding to provided ACS URL: '{}'",
                getSpAssertionConsumerService());

        List<Endpoint> endpoints = getEntityRoleMetadata().getEndpoints();
        log.debug("Relying party role contains '{}' endpoints", endpoints.size());

        if (endpoints != null && endpoints.size() > 0) {
            for (Endpoint endpoint : endpoints) {
                if (endpoint == null || !getSupportedIssuerBindings().contains(endpoint.getBinding())) {
                    continue;
                }

                if (endpoint.getLocation().equalsIgnoreCase(spAssertionConsumerService)) {
                    return endpoint;
                }

                if (!DatatypeHelper.isEmpty(endpoint.getResponseLocation())
                        && endpoint.getResponseLocation().equalsIgnoreCase(spAssertionConsumerService)) {
                    return endpoint;
                }
            }
        }

        log.debug("No endpoint meets selection criteria for SAML entity '{}'", getEntityMetadata().getEntityID());
        return null;
    }
}