/*
 * Copyright [2007] [University Corporation for Advanced Internet Development, Inc.]
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

package edu.internet2.middleware.shibboleth.idp.profile.saml1;

import java.util.List;

import org.opensaml.common.binding.BasicEndpointSelector;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.xml.util.DatatypeHelper;

/**
 * An endpoint selector that may optionally take a SP-provided assertion consumer service URL, validate it against
 * metadata, and return an endpoint based on it. If no URL is provided the {@link BasicEndpointSelector} selection is
 * used.
 */
public class ShibbolethSSOEndpointSelector extends BasicEndpointSelector {

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
        List<Endpoint> endpoints = getEntityRoleMetadata().getEndpoints();
        if (endpoints != null) {
            for (Endpoint endpoint : endpoints) {
                if (endpoint.getLocation().equalsIgnoreCase(spAssertionConsumerService)
                        || endpoint.getResponseLocation().equalsIgnoreCase(spAssertionConsumerService)) {
                    return endpoint;
                }
            }
        }

        return null;
    }
}