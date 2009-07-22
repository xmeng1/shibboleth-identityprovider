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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Adam Lantos  NIIF / HUNGARNET
 */
public class SingleLogoutContext implements Serializable {

    private static final long serialVersionUID = -6824272239830757989L;
    /** EntityID of the entity which requested the logout. */
    private final String requesterEntityID;
    /** EntityID of the IdP which will respond. */
    private final String responderEntityID;
    /** SAML ID of the LogoutRequest. */
    private final String requestSAMLMessageID;
    /** RelayState of the LogoutRequest. */
    private final String relayState;
    /** URL of the current profile handler. */
    private final String profileHandlerURL;
    private final Map<String, LogoutInformation> serviceInformation;

    public SingleLogoutContext(
            String profileHandlerURL,
            String requesterEntityID,
            String responderEntityID,
            String requestSAMLMessageID,
            String relayState,
            Session idpSession) {

        this.profileHandlerURL = profileHandlerURL;
        this.requesterEntityID = requesterEntityID;
        this.responderEntityID = responderEntityID;
        this.requestSAMLMessageID = requestSAMLMessageID;
        this.relayState = relayState;

        Map<String, ServiceInformation> serviceInformationMap =
                idpSession.getServicesInformation();
        Map<String, LogoutInformation> serviceInfo =
                new HashMap<String, LogoutInformation>(serviceInformationMap.size());
        for (ServiceInformation service : serviceInformationMap.values()) {
            if (!service.getEntityID().equals(requesterEntityID)) {
                LogoutInformation logoutInfo =
                        new LogoutInformation(service, LogoutStatus.LOGGED_IN);
                serviceInfo.put(service.getEntityID(), logoutInfo);
            }
        }
        this.serviceInformation = Collections.unmodifiableMap(serviceInfo);
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

    public String getResponderEntityID() {
        return responderEntityID;
    }

    public String getProfileHandlerURL() {
        return profileHandlerURL;
    }

    public Map<String, LogoutInformation> getServiceInformation() {
        synchronized (this) {
            return serviceInformation;
        }
    }

    /**
     * Returns the next service which is in LOGGED_IN state or null.
     * 
     * @return
     */
    public LogoutInformation getNextActiveService() {
        synchronized (this) {
            for (LogoutInformation serviceLogoutInfo : serviceInformation.values()) {
                if (serviceLogoutInfo.getLogoutStatus().equals(LogoutStatus.LOGGED_IN)) {
                    return serviceLogoutInfo;
                }
            }

            return null;
        }
    }

    public enum LogoutStatus implements Serializable {

        LOGGED_IN, LOGOUT_ATTEMPTED, LOGOUT_SUCCEEDED, LOGOUT_FAILED
    }

    public class LogoutInformation implements Serializable {
        
        private static final long serialVersionUID = -9214161647487117263L;
        
        private final String entityID;
        private final String nameIdentifier;
        private final String nameIdentifierFormat;
        private LogoutStatus logoutStatus;
        private String logoutRequestId;

        public LogoutInformation(String entityID, String nameIdentifier,
                String nameIdentifierFormat, LogoutStatus logoutStatus) {

            this.entityID = entityID;
            this.nameIdentifier = nameIdentifier;
            this.nameIdentifierFormat = nameIdentifierFormat;
            this.logoutStatus = logoutStatus;
        }

        public LogoutInformation(ServiceInformation service, LogoutStatus status) {
            this(service.getEntityID(), service.getNameIdentifier(),
                    service.getNameIdentifierFormat(), status);
        }

        public String getEntityID() {
            return entityID;
        }

        public LogoutStatus getLogoutStatus() {
            synchronized (this) {
                return logoutStatus;
            }
        }

        public void setLogoutStatus(LogoutStatus logoutStatus) {
            synchronized (this) {
                this.logoutStatus = logoutStatus;
            }
        }

        public String getNameIdentifier() {
            return nameIdentifier;
        }

        public String getNameIdentifierFormat() {
            return nameIdentifierFormat;
        }

        public String getLogoutRequestId() {
            synchronized (this) {
                return logoutRequestId;
            }
        }

        public void setLogoutRequestId(String logoutRequestId) {
            synchronized (this) {
                if (this.logoutRequestId == null) {
                    this.logoutRequestId = logoutRequestId;
                } else {
                    throw new IllegalStateException("Request ID is previously set");
                }
            }
        }
    }
}
