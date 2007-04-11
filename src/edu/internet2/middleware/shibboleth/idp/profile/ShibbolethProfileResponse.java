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

import javax.servlet.http.HttpServletResponse;

import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BindingException;
import org.opensaml.common.binding.MessageEncoder;
import org.opensaml.xml.XMLObject;

import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;

/**
 * Shibboleth {@link ProfileResponse}.
 */
public class ShibbolethProfileResponse implements ProfileResponse<HttpServletResponse> {

    /** Encoder used to send the response. */
    private MessageEncoder<HttpServletResponse> messageEncoder;

    /** The outgoing response. */
    private HttpServletResponse rawResponse;

    /**
     * Constructor.
     * 
     * @param response the raw response
     * @param encoder the encoder used to encode the response
     */
    public ShibbolethProfileResponse(HttpServletResponse response, MessageEncoder<HttpServletResponse> encoder) {
        rawResponse = response;
        messageEncoder = encoder;
    }

    /** {@inheritDoc} */
    public MessageEncoder<HttpServletResponse> getMessageEncoder() {
        return messageEncoder;
    }

    /** {@inheritDoc} */
    public HttpServletResponse getRawResponse() {
        return rawResponse;
    }

    /**
     * {@inheritDoc}
     * 
     * @throws BindingException thrown if the message can not be encoded and sent to the relying party
     */
    public void sendResponse(XMLObject response) throws BindingException {
        messageEncoder.setResponse(rawResponse);
        messageEncoder.setSAMLMessage((SAMLObject) response);
        messageEncoder.encode();
    }
}