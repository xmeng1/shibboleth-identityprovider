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

package edu.internet2.middleware.shibboleth.idp.profile.saml2;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.SSOConfiguration;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;

/**
 * SAML 2.0 authentication request profile handler.
 */
public class AuthenticationRequestProfileHandler extends AbstractSAML2ProfileHandler {

    /** {@inheritDoc} */
    public String getProfileId() {
        return "urn:mace:shibboleth:2.0:idp:profiles:saml2:request:authentication";
    }

    /** {@inheritDoc} */
    public void processRequest(ProfileRequest<ServletRequest> request, ProfileResponse<ServletResponse> response)
            throws ProfileException {

    }

    /**
     * Represents the internal state of a SAML 2.0 Authentiation Request while it's being processed by the IdP.
     */
    protected class AuthenticationRequestContext extends
            SAML2ProfileRequestContext<AuthnRequest, Response, SSOConfiguration> {

        /** The IdP's LoginContext. */
        private LoginContext loginContext;

        /**
         * Constructor.
         * 
         * @param request current profile request
         * @param response current profile response
         */
        public AuthenticationRequestContext(ProfileRequest<ServletRequest> request,
                ProfileResponse<ServletResponse> response) {
            super(request, response);
        }

        /**
         * Gets the login context for this request.
         * 
         * @return login context for this request
         */
        public LoginContext getLoginContext() {
            return loginContext;
        }

        /**
         * Sets the login context for this request.
         * 
         * @param context login context for this request
         */
        public void setLoginContext(LoginContext context) {
            loginContext = context;
        }
    }
}