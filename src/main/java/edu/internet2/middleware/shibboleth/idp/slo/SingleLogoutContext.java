/*
 *  Copyright 2009 NIIF Institute.
 * 
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *  under the License.
 */

package edu.internet2.middleware.shibboleth.idp.slo;

import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;
import edu.internet2.middleware.shibboleth.idp.session.Session;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Adam Lantos  NIIF / HUNGARNET
 */
public class SingleLogoutContext implements Serializable {
    
    private static final long serialVersionUID = -4067880011119487071L;

    /** EntityID of the entity which requested the logout. */
    private final String requesterEntityID;

    /** SAML ID of the LogoutRequest. */
    private final String requestSAMLMessageID;

    /** RelayState of the LogoutRequest. */
    private final String relayState;

    private final Map<String, LogoutStatus> serviceStatus;

    public SingleLogoutContext(
            String requesterEntityID, String requestSAMLMessageID,
            String relayState, Session idpSession) {
        
        this.requesterEntityID = requesterEntityID;
        this.requestSAMLMessageID = requestSAMLMessageID;
        this.relayState = relayState;

        Map<String, ServiceInformation> serviceInformationMap = idpSession.getServicesInformation();
        this.serviceStatus = new HashMap<String, LogoutStatus>(serviceInformationMap.size());
        for (ServiceInformation service : serviceInformationMap.values()) {
            if (!service.getEntityID().equals(requesterEntityID)) {
                serviceStatus.put(service.getEntityID(), LogoutStatus.LOGGED_IN);
            }
        }
    }

    public String getRelayState() {
        return relayState;
    }

    public String getRequestSAMLMessageID() {
        return requestSAMLMessageID;
    }

    public String getRequesterEntityID() {
        return requesterEntityID;
    }

    public Map<String, LogoutStatus> getServiceStatus() {
        return serviceStatus;
    }
    
    public enum LogoutStatus implements Serializable {
        LOGGED_IN, LOGOUT_ATTEMPTED, LOGOUT_SUCCEEDED, LOGOUT_FAILED
    }
}
