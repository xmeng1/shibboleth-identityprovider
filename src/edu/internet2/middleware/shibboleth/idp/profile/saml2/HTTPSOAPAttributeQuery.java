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

import org.opensaml.common.binding.decoding.MessageDecoder;
import org.opensaml.common.binding.encoding.MessageEncoder;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;

/**
 * SAML 2.0 SOAP Attribute Query profile handler.
 */
public class HTTPSOAPAttributeQuery extends AbstractAttributeQuery {

    /** SAML binding URI. */
    public static final String BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";

    /** Constructor. */
    public HTTPSOAPAttributeQuery() {
        super();
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    protected void getMessageDecoder(AttributeQueryRequestContext requestContext) throws ProfileException {
        MessageDecoder<ServletRequest> decoder = getMessageDecoderFactory().getMessageDecoder(BINDING);
        if (decoder == null) {
            throw new ProfileException("No request decoder was registered for binding type: " + BINDING);
        }

        requestContext.setMessageDecoder(decoder);
        decoder.setRequest(requestContext.getProfileRequest().getRawRequest());
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    protected void getMessageEncoder(AttributeQueryRequestContext requestContext) throws ProfileException {

        MessageEncoder<ServletResponse> encoder = getMessageEncoderFactory().getMessageEncoder(BINDING);
        if (encoder == null) {
            throw new ProfileException("No response encoder was registered for binding type: " + BINDING);
        }

        requestContext.setMessageEncoder(encoder);
        encoder.setResponse(requestContext.getProfileResponse().getRawResponse());
        encoder.setSamlMessage(requestContext.getAttributeQueryResponse());
    }
}