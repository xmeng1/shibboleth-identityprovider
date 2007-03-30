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

import javax.servlet.ServletRequest;

import org.opensaml.common.binding.MessageDecoder;

import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;

/**
 * Shibboleth {@link ProfileRequest}.
 */
public class ShibbolethProfileRequest implements ProfileRequest {

    /** Request to process. */
    private ServletRequest request;

    /** For decoding requests. */
    private MessageDecoder<ServletRequest> messageDecoder;

    /**
     * Constructor.
     * 
     * @param r to process
     * @param d for decoding the servlet request
     */
    public ShibbolethProfileRequest(ServletRequest r, MessageDecoder<ServletRequest> d) {
        request = r;
        messageDecoder = d;
    }

    /** {@inheritDoc} */
    public ServletRequest getRequest() {
        return request;
    }

    /** {@inheritDoc} */
    public MessageDecoder<ServletRequest> getMessageDecoder() {
        return messageDecoder;
    }
}
