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

package edu.internet2.middleware.shibboleth.idp.profile;

import javax.servlet.http.HttpServletRequest;

import org.opensaml.common.binding.MessageDecoder;

import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyManager;
import edu.internet2.middleware.shibboleth.common.session.SessionManager;
import edu.internet2.middleware.shibboleth.idp.session.Session;

/**
 * Shibboleth {@link ProfileRequest}.
 */
public class ShibbolethProfileRequest implements ProfileRequest<HttpServletRequest, Session> {

    /** The in comming request. */
    private HttpServletRequest rawRequest;

    /** Configuration information for the requesting party. */
    private RelyingPartyConfiguration rpConfiguration;

    /** The current user session. */
    private Session userSession;

    /**
     * Constructor.
     * 
     * @param request the incomming HTTP request
     * @param decoder the decoder for the request, all information but the request must be set already
     * @param sessionManager the manager of current user sessions
     * @param rpConfigManager the relying party configuration manager
     */
    public ShibbolethProfileRequest(HttpServletRequest request, MessageDecoder<HttpServletRequest> decoder,
            SessionManager<Session> sessionManager, RelyingPartyManager rpConfigManager){

        rawRequest = request;
        userSession = sessionManager.getSession(request.getSession().getId());
    }

    /** {@inheritDoc} */
    public HttpServletRequest getRawRequest() {
        return rawRequest;
    }

    /** {@inheritDoc} */
    public RelyingPartyConfiguration getRelyingPartyConfiguration() {
        return rpConfiguration;
    }

    /** {@inheritDoc} */
    public Session getSession() {
        return userSession;
    }
}