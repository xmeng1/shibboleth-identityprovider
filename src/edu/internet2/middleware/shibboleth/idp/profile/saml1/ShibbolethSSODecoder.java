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

import org.apache.log4j.Logger;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.decoder.BaseMessageDecoder;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.xml.util.DatatypeHelper;

import edu.internet2.middleware.shibboleth.idp.profile.saml1.ShibbolethSSOProfileHandler.ShibbolethSSORequestContext;

/**
 * Shibboleth 1.0 SSO authentication request message decoder.
 */
public class ShibbolethSSODecoder extends BaseMessageDecoder implements SAMLMessageDecoder {

    /** Class logger. */
    private final Logger log = Logger.getLogger(ShibbolethSSODecoder.class);

    /** {@inheritDoc} */
    public String getBindingURI() {
        return "urn:mace:shibboleth:1.0:profiles:AuthnRequest";
    }

    /** {@inheritDoc} */
    protected void doDecode(MessageContext messageContext) throws MessageDecodingException {
        if (!(messageContext instanceof ShibbolethSSORequestContext)) {
            log.error("Invalid message context type, this decoder only support ShibbolethSSORequestContext");
            throw new MessageDecodingException(
                    "Invalid message context type, this decoder only support ShibbolethSSORequestContext");
        }

        if (!(messageContext.getInboundMessageTransport() instanceof HTTPInTransport)) {
            log.error("Invalid inbound message transport type, this decoder only support HTTPInTransport");
            throw new MessageDecodingException(
                    "Invalid inbound message transport type, this decoder only support HTTPInTransport");
        }

        ShibbolethSSORequestContext requestContext = (ShibbolethSSORequestContext) messageContext;
        HTTPInTransport transport = (HTTPInTransport) messageContext.getInboundMessage();

        String providerId = DatatypeHelper.safeTrimOrNullString(transport.getParameterValue("providerId"));
        if (providerId == null) {
            log.error("No providerId parameter given in Shibboleth SSO authentication request.");
            throw new MessageDecodingException(
                    "No providerId parameter given in Shibboleth SSO authentication request.");
        }
        requestContext.setPeerEntityId(providerId);

        String shire = DatatypeHelper.safeTrimOrNullString(transport.getParameterValue("shire"));
        if (shire == null) {
            log.error("No shire parameter given in Shibboleth SSO authentication request.");
            throw new MessageDecodingException("No shire parameter given in Shibboleth SSO authentication request.");
        }
        requestContext.setSpAssertionConsumerService(shire);

        String target = DatatypeHelper.safeTrimOrNullString(transport.getParameterValue("target"));
        if (target == null) {
            log.error("No target parameter given in Shibboleth SSO authentication request.");
            throw new MessageDecodingException("No target parameter given in Shibboleth SSO authentication request.");
        }
        requestContext.setRelayState(target);

        String timeStr = DatatypeHelper.safeTrimOrNullString(transport.getParameterValue("time"));
        if (timeStr != null) {
            long time = Long.parseLong(timeStr);
            requestContext.setTime(time);
        }
    }
}