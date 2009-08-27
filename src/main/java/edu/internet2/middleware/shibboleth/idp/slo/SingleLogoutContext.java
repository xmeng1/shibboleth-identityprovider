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

import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.LogoutRequestConfiguration;
import edu.internet2.middleware.shibboleth.idp.profile.saml2.SLOProfileHandler.InitialLogoutRequestContext;
import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;
import edu.internet2.middleware.shibboleth.idp.session.Session;
import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Context object for storing information associated with a Single Logout
 * event.
 *
 * The SingleLogoutContext holds all information of the SAML LogoutRequest
 * which is needed to respond (RelayState, ID, EntityID). SingleLogoutContext
 * also stores the status of the Logout for each session participant.
 *
 * @author Adam Lantos  NIIF / HUNGARNET
 */
public class SingleLogoutContext implements Serializable {

    private static final long serialVersionUID = -2386684678331311278L;
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
    /** Internal IdP Session ID. */
    private final String idpSessionID;
    /** Timeout value for frontchannel requests (in milliseconds). */
    private final int frontChannelResponseTimeout;
    /** Logout information associated with each session participant. */
    private final Map<String, LogoutInformation> serviceInformation;

    /**
     * Private constructor to create a new SingleLogoutContext instance.
     * 
     * @param profileHandlerURL URL for the SLO profile handler
     * @param requesterEntityID entityID of the requester SP (may be null)
     * @param responderEntityID entityID of the IdP
     * @param requestSAMLMessageID ID of the SAML LogoutRequest message
     * @param relayState RelayState associated with the LogoutRequest
     * @param profileConfiguration Single Logout profile configuration
     * @param idpSession IdP session for the principal
     */
    private SingleLogoutContext(
            String profileHandlerURL,
            String requesterEntityID,
            String responderEntityID,
            String requestSAMLMessageID,
            String relayState,
            LogoutRequestConfiguration profileConfiguration,
            Session idpSession) {

        this.profileHandlerURL = profileHandlerURL;
        this.requesterEntityID = requesterEntityID;
        this.responderEntityID = responderEntityID;
        this.requestSAMLMessageID = requestSAMLMessageID;
        this.relayState = relayState;
        this.frontChannelResponseTimeout =
                profileConfiguration.getFrontChannelResponseTimeout();
        this.idpSessionID = idpSession.getSessionID();

        Map<String, ServiceInformation> serviceInformationMap =
                idpSession.getServicesInformation();
        Map<String, LogoutInformation> serviceInfo =
                new HashMap<String, LogoutInformation>(serviceInformationMap.size());
        for (ServiceInformation service : serviceInformationMap.values()) {
            LogoutInformation logoutInfo;
            if (!service.getEntityID().equals(requesterEntityID)) {
                logoutInfo =
                        new LogoutInformation(service, LogoutStatus.LOGGED_IN);
            } else {
                logoutInfo =
                        new LogoutInformation(service, LogoutStatus.LOGOUT_SUCCEEDED);
            }
            serviceInfo.put(service.getEntityID(), logoutInfo);
        }
        this.serviceInformation = Collections.unmodifiableMap(serviceInfo);
    }

    /**
     * Create a new instance of SingleLogoutContext.
     * 
     * @param profileHandlerURL URL of the SLO profile handler
     * @param initialRequest initial logout request
     * @param idpSession IdP session for the principal
     * @return
     */
    public final static SingleLogoutContext createInstance(
            String profileHandlerURL,
            InitialLogoutRequestContext initialRequest,
            Session idpSession) {

        return new SingleLogoutContext(
                profileHandlerURL,
                initialRequest.getPeerEntityId(),
                initialRequest.getLocalEntityId(),
                initialRequest.getInboundSAMLMessageId(),
                initialRequest.getRelayState(),
                initialRequest.getProfileConfiguration(),
                idpSession);
    }

    /**
     * Returns the RelayState of the initial SAML LogoutRequest (if any).
     * 
     * @return RelayState or NULL
     */
    public String getRelayState() {
        return relayState;
    }

    /**
     * Returns the ID of the initial SAML LogoutRequest message.
     *
     * @return message ID or NULL if the logout is IdP-initiated
     */
    public String getRequestSAMLMessageID() {
        return requestSAMLMessageID;
    }

    /**
     * Returns the entityID of the requesting session participant.
     *
     * @return entityID or NULL if the logout is IdP-initiated
     */
    public String getRequesterEntityID() {
        return requesterEntityID;
    }

    /**
     * Returns the entityID of the IdP itself.
     *
     * @return entityID of the IdP
     */
    public String getResponderEntityID() {
        return responderEntityID;
    }

    /**
     * Returns the Single Logout profile handler URL which must be invoked when
     * the Logout process is finished.
     * 
     * @return profile handler URL
     */
    public String getProfileHandlerURL() {
        return profileHandlerURL;
    }

    /**
     * Returns the session ID of the principal.
     *
     * @return session ID
     */
    public String getIdpSessionID() {
        return idpSessionID;
    }

    /**
     * Returns the logout information associated with each session participant.
     *
     * @return logout information for session participants
     */
    public Map<String, LogoutInformation> getServiceInformation() {
        return serviceInformation;
    }

    /**
     * Checks all services for logout timeout. This method must be called
     * before the front channel logout status is determined and returned back
     * to the client.
     */
    public synchronized void checkTimeout() {
        for (LogoutInformation serviceLogoutInfo : serviceInformation.values()) {
            if (serviceLogoutInfo.getLogoutStatus().equals(LogoutStatus.LOGOUT_ATTEMPTED) &&
                    serviceLogoutInfo.getElapsedMillis() >
                    frontChannelResponseTimeout) {
                serviceLogoutInfo.setLogoutTimedOut();
            }
        }
    }

    /**
     * Logout Status for a session participant.
     */
    public enum LogoutStatus implements Serializable {

        LOGGED_IN, LOGOUT_ATTEMPTED, LOGOUT_SUCCEEDED, LOGOUT_FAILED,
        LOGOUT_UNSUPPORTED, LOGOUT_TIMED_OUT
    }

    /**
     * Class for holding all information associated with a session participant
     * during the single logout process.
     *
     * @author Adam Lantos  NIIF / HUNGARNET
     */
    public class LogoutInformation implements Serializable {

        private static final long serialVersionUID = -1371240803047042613L;
        /** entityID of the SP */
        private final String entityID;
        /** name identifier value issued for the principal to this SP. */
        private final String nameIdentifier;
        /** name identifier format. */
        private final String nameIdentifierFormat;
        /** qualifier for the name identifier. */
        private final String nameQualifier;
        /** SP name qualifier for the name identifier (SAML2 case only). */
        private final String SPNameQualifier;
        /** status of the logout process. */
        private LogoutStatus logoutStatus;
        /** SAML logout request ID. */
        private String logoutRequestId;
        /** SP display names from the Metadata. */
        private Map<String, String> displayName;
        /** timestamp of the logout request. */
        private long logoutTimestamp;

        /**
         * Creates new LogoutInformation instance.
         *
         * @param entityID SP entityID
         * @param nameIdentifier identifier value issued for the principal
         * @param nameIdentifierFormat name identifier format
         * @param nameQualifier name qualifier
         * @param SPNameQualifier SP name qualifier
         * @param logoutStatus status of the logout
         */
        LogoutInformation(String entityID, String nameIdentifier,
                String nameIdentifierFormat, String nameQualifier,
                String SPNameQualifier, LogoutStatus logoutStatus) {

            this.entityID = entityID;
            this.nameIdentifier = nameIdentifier;
            this.nameIdentifierFormat = nameIdentifierFormat;
            this.nameQualifier = nameQualifier;
            this.SPNameQualifier = SPNameQualifier;
            this.logoutStatus = logoutStatus;
        }

        /**
         * Creates new LogoutInformation instance.
         *
         * @param service session participant service information
         * @param status status of the logout
         */
        LogoutInformation(ServiceInformation service, LogoutStatus status) {
            this(service.getEntityID(), service.getNameIdentifier(),
                    service.getNameIdentifierFormat(), service.getNameQualifier(),
                    service.getSPNameQualifier(), status);
        }

        /**
         * Returns the entityID of the session participant.
         *
         * @return entityID
         */
        public String getEntityID() {
            return entityID;
        }

        /**
         * Returns the status of the logout.
         *
         * @return status of the logout.
         */
        public synchronized LogoutStatus getLogoutStatus() {
            return logoutStatus;
        }

        /**
         * Sets status of the logout.
         *
         * @param logoutStatus status of the logout
         */
        private void setLogoutStatus(LogoutStatus logoutStatus) {
            this.logoutStatus = logoutStatus;
        }

        /**
         * Sets status to LOGOUT_UNSUPPORTED.
         * @throws IllegalStateException  when logout status is not LOGGED_IN.
         */
        public synchronized void setLogoutUnsupported() {
            if (getLogoutStatus().equals(LogoutStatus.LOGGED_IN)) {
                this.setLogoutStatus(LogoutStatus.LOGOUT_UNSUPPORTED);
            } else {
                throw new IllegalStateException("LogoutStatus is not LOGGED_IN");
            }
        }

        /**
         * Sets status to LOGOUT_ATTEMPTED.
         * @throws IllegalStateException when logout status is not LOGGED_IN.
         */
        public synchronized void setLogoutAttempted() {
            if (getLogoutStatus().equals(LogoutStatus.LOGGED_IN)) {
                this.setLogoutStatus(LogoutStatus.LOGOUT_ATTEMPTED);
                this.logoutTimestamp = System.currentTimeMillis();
            } else {
                throw new IllegalStateException("Logout already attempted");
            }
        }

        /**
         * Sets status to LOGOUT_FAILED.
         * @throws IllegalStateException when logout status is not LOGOUT_ATTEMPTED.
         */
        public synchronized void setLogoutFailed() {
            if (getLogoutStatus().equals(LogoutStatus.LOGOUT_ATTEMPTED)) {
                this.setLogoutStatus(LogoutStatus.LOGOUT_FAILED);
            } else {
                throw new IllegalStateException("LogoutStatus is not LOGOUT_ATTEMPTED");
            }
        }

        /**
         * Sets status to LOGOUT_SUCCEEDED.
         * @throws IllegalStateException when logout status is not LOGOUT_ATTEMPTED.
         */
        public synchronized void setLogoutSucceeded() {
            if (getLogoutStatus().equals(LogoutStatus.LOGOUT_ATTEMPTED)) {
                this.setLogoutStatus(LogoutStatus.LOGOUT_SUCCEEDED);
            } else {
                throw new IllegalStateException("LogoutStatus is not LOGOUT_ATTEMPTED");
            }
        }

        /**
         * Sets status to LOGOUT_TIMED_OUT.
         * @throws IllegalStateException when logout status is not LOGOUT_ATTEMPTED.
         */
        public synchronized void setLogoutTimedOut() {
            if (getLogoutStatus().equals(LogoutStatus.LOGOUT_ATTEMPTED)) {
                this.setLogoutStatus(LogoutStatus.LOGOUT_TIMED_OUT);
            } else {
                throw new IllegalStateException("LogoutStatus is not LOGOUT_ATTEMPTED");
            }
        }

        /**
         * Returns whether this service is still in LOGGED_IN state.
         * @return
         */
        public boolean isLoggedIn() {
            return getLogoutStatus().equals(LogoutStatus.LOGGED_IN);
        }

        /**
         * Returns the name identifier for the principal at this SP.
         * @return name identifier
         */
        public String getNameIdentifier() {
            return nameIdentifier;
        }

        /**
         * Returns name identifier format for the principal at this SP.
         *
         * @return name identifier format
         */
        public String getNameIdentifierFormat() {
            return nameIdentifierFormat;
        }

        /**
         * Returns the name qualifier for the principal at this SP.
         *
         * @return name qualifier or NULL
         */
        public String getNameQualifier() {
            return nameQualifier;
        }

        /**
         * Returns the SP name qualifier for the principal at this SP.
         *
         * @return SP name qualifier or NULL
         */
        public String getSPNameQualifier() {
            return SPNameQualifier;
        }

        /**
         * Returns the ID of the SAML logout request.
         *
         * @return SAML logout request ID
         */
        public synchronized String getLogoutRequestId() {
            return logoutRequestId;
        }

        /**
         * Sets the SAML logout request ID. This method must be called once.
         *
         * @param logoutRequestId SAML logout request ID
         */
        public synchronized void setLogoutRequestId(String logoutRequestId) {
            if (this.logoutRequestId == null) {
                this.logoutRequestId = logoutRequestId;
            } else {
                throw new IllegalStateException("Request ID is previously set");
            }
        }

        /**
         * Sets localized display names for this SP. This method must be called once.
         *
         * @param displayName map of language and display name
         */
        public synchronized void setDisplayName(Map<String, String> displayName) {
            if (this.displayName == null) {
                this.displayName = Collections.unmodifiableMap(displayName);
            } else {
                throw new IllegalStateException("Display Name is previously set");
            }
        }

        /**
         * Returns localized display name for the SP.
         * If no display name is found for the given languages, the entityID
         * is returned.
         *
         * @param locale locale defined by the user agent
         * @param defaultLocale default fallback locale
         * @return localized display name or the entityID
         */
        public String getDisplayName(Locale locale, Locale defaultLocale) {
            String dName = null;
            if (displayName != null) {
                if (locale != null) {
                    dName = displayName.get(locale.getLanguage());
                }
                if (dName == null && defaultLocale != null) {
                    dName = displayName.get(defaultLocale.getLanguage());
                }
            }
            if (dName == null) {
                dName = entityID;
            }

            return dName;
        }

        /**
         * Returns the elapsed milliseconds since the logout request is sent.
         * This method must only be called when the request timestamp is set.
         *
         * @return elapsed millisenconds since logout initiation
         */
        long getElapsedMillis() {
            if (this.logoutTimestamp == 0) {
                throw new IllegalStateException("Logout timestamp is not initialized");
            }

            return System.currentTimeMillis() - logoutTimestamp;
        }
    }
}
