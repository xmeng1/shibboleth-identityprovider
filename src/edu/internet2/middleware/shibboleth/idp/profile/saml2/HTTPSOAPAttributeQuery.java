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
import javax.servlet.http.HttpServletRequest;

import org.opensaml.common.binding.MessageDecoder;
import org.opensaml.common.binding.MessageEncoder;
import org.opensaml.saml2.binding.HTTPSOAP11Decoder;
import org.opensaml.saml2.binding.HTTPSOAP11Encoder;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;
import edu.internet2.middleware.shibboleth.idp.session.Session;

/**
 * SAML 2.0 SOAP Attribute Query profile handler.
 */
public class HTTPSOAPAttributeQuery extends AbstractAttributeQuery {

    /** Constructor. */
    public HTTPSOAPAttributeQuery() {
        super();
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    protected MessageDecoder<ServletRequest> getMessageDecoder(ProfileRequest<ServletRequest> request)
            throws ProfileException {
        MessageDecoder decoder = new HTTPSOAP11Decoder();
        decoder.setRequest(request.getRawRequest());
        return decoder;
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    protected MessageEncoder<ServletResponse> getMessageEncoder(ProfileResponse<ServletResponse> response)
            throws ProfileException {
        MessageEncoder encoder = new HTTPSOAP11Encoder();
        encoder.setResponse(response.getRawResponse());
        return encoder;
    }

    /** {@inheritDoc} */
    protected String getUserSessionId(ProfileRequest<ServletRequest> request) {
        HttpServletRequest rawRequest = (HttpServletRequest) request.getRawRequest();
        if (rawRequest != null) {
            return (String) rawRequest.getSession().getAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE);
        }

        return null;
    }
}