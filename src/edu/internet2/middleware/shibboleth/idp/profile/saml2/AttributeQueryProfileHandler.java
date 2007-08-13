/*
 * Copyright [2006] [University Corporation for Advanced Internet Development, Inc.]
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

import java.util.ArrayList;

import org.apache.log4j.Logger;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Statement;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.metadata.AttributeAuthorityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.security.SecurityPolicyException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.AttributeQueryConfiguration;

/** SAML 2.0 Attribute Query profile handler. */
public class AttributeQueryProfileHandler extends AbstractSAML2ProfileHandler {

    /** Class logger. */
    private static Logger log = Logger.getLogger(AttributeQueryProfileHandler.class);

    /** {@inheritDoc} */
    public String getProfileId() {
        return "urn:mace:shibboleth:2.0:idp:profiles:saml2:query:attribute";
    }

    /** {@inheritDoc} */
    public void processRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport) throws ProfileException {
        Response samlResponse;

        AttributeQueryContext requestContext = decodeRequest(inTransport, outTransport);

        try {
            if (requestContext.getRelyingPartyConfiguration() == null) {
                log.error("SAML 2 Attribute Query profile is not configured for relying party "
                        + requestContext.getRelyingPartyEntityId());
                requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, StatusCode.REQUEST_DENIED_URI,
                        "SAML 2 Attribute Query profile is not configured for relying party "
                                + requestContext.getRelyingPartyEntityId()));
                samlResponse = buildErrorResponse(requestContext);
            }

            checkSamlVersion(requestContext);

            // Resolve attribute query name id to principal name and place in context
            resolvePrincipal(requestContext);

            resolveAttributes(requestContext);

            // Lookup principal name and attributes, create attribute statement from information
            ArrayList<Statement> statements = new ArrayList<Statement>();
            statements.add(buildAttributeStatement(requestContext));

            // create the SAML response
            samlResponse = buildResponse(requestContext, "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches", statements);
        } catch (ProfileException e) {
            samlResponse = buildErrorResponse(requestContext);
        }

        requestContext.setOutboundSAMLMessage(samlResponse);
        requestContext.setOutboundSAMLMessageId(samlResponse.getID());
        requestContext.setOutboundSAMLMessageIssueInstant(samlResponse.getIssueInstant());

        encodeResponse(requestContext);
        writeAuditLogEntry(requestContext);
    }

    /**
     * Decodes an incoming request and populates a created request context with the resultant information.
     * 
     * @param inTransport inbound message transport
     * @param outTransport outbound message transport
     * 
     * @return the created request context
     * 
     * @throws ProfileException throw if there is a problem decoding the request
     */
    protected AttributeQueryContext decodeRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport)
            throws ProfileException {
        if (log.isDebugEnabled()) {
            log.debug("Decoding incomming request");
        }

        MetadataProvider metadataProvider = getMetadataProvider();

        AttributeQueryContext requestContext = new AttributeQueryContext();
        requestContext.setMessageInTransport(inTransport);
        requestContext.setInboundSAMLProtocol(SAMLConstants.SAML20P_NS);
        requestContext.setMessageOutTransport(outTransport);
        requestContext.setOutboundSAMLProtocol(SAMLConstants.SAML20P_NS);
        requestContext.setMetadataProvider(metadataProvider);

        try {
            getMessageDecoder().decode(requestContext);
            if (log.isDebugEnabled()) {
                log.debug("Decoded request");
            }
            return requestContext;
        } catch (MessageDecodingException e) {
            log.error("Error decoding attribute query message", e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null, "Error decoding message"));
            throw new ProfileException("Error decoding attribute query message");
        } catch (SecurityPolicyException e) {
            log.error("Message did not meet security policy requirements", e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, StatusCode.REQUEST_DENIED_URI,
                    "Message did not meet security policy requirements"));
            throw new ProfileException("Message did not meet security policy requirements", e);
        } finally {
            // Set as much information as can be retrieved from the decoded message
            try {
                AttributeQuery attributeQuery = requestContext.getInboundSAMLMessage();
                requestContext.setInboundSAMLMessageId(attributeQuery.getID());
                requestContext.setInboundSAMLMessageIssueInstant(attributeQuery.getIssueInstant());

                String relyingPartyId = requestContext.getRelyingPartyEntityId();
                requestContext.setRelyingPartyMetadata(metadataProvider.getEntityDescriptor(relyingPartyId));
                requestContext.setRelyingPartyRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
                requestContext.setRelyingPartyRoleMetadata(requestContext.getRelyingPartyMetadata().getSPSSODescriptor(
                        SAMLConstants.SAML20P_NS));
                RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(relyingPartyId);
                requestContext.setRelyingPartyConfiguration(rpConfig);

                String assertingPartyId = requestContext.getRelyingPartyConfiguration().getProviderId();
                requestContext.setAssertingPartyEntityId(assertingPartyId);
                requestContext.setAssertingPartyMetadata(metadataProvider.getEntityDescriptor(assertingPartyId));
                requestContext.setAssertingPartyRole(AttributeAuthorityDescriptor.DEFAULT_ELEMENT_NAME);
                requestContext.setAssertingPartyRoleMetadata(requestContext.getAssertingPartyMetadata()
                        .getAttributeAuthorityDescriptor(SAMLConstants.SAML20P_NS));

                AttributeQueryConfiguration profileConfig = (AttributeQueryConfiguration) rpConfig
                        .getProfileConfiguration(AttributeQueryConfiguration.PROFILE_ID);
                requestContext.setProfileConfiguration(profileConfig);
                if (profileConfig.getSigningCredential() != null) {
                    requestContext.setOutboundSAMLMessageSigningCredential(profileConfig.getSigningCredential());
                } else if (rpConfig.getDefaultSigningCredential() != null) {
                    requestContext.setOutboundSAMLMessageSigningCredential(rpConfig.getDefaultSigningCredential());
                }

            } catch (MetadataProviderException e) {
                log.error("Unable to locate metadata for asserting or relying party");
                requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null,
                        "Error locating party metadata"));
                throw new ProfileException("Error locating party metadata");
            }
        }
    }

    /**
     * Encodes the request's SAML response and writes it to the servlet response.
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if no message encoder is registered for this profiles binding
     */
    protected void encodeResponse(AttributeQueryContext requestContext) throws ProfileException {
        if (log.isDebugEnabled()) {
            log.debug("Encoding response to SAML request " + requestContext.getInboundSAMLMessageId()
                    + " from relying party " + requestContext.getRelyingPartyEntityId());
        }

        try {
            getMessageEncoder().encode(requestContext);
        } catch (MessageEncodingException e) {
            throw new ProfileException("Unable to encode response to relying party: "
                    + requestContext.getRelyingPartyEntityId(), e);
        }
    }

    /** Basic data structure used to accumulate information as a request is being processed. */
    protected class AttributeQueryContext extends
            BaseSAML2ProfileRequestContext<AttributeQuery, Response, AttributeQueryConfiguration> {

    }
}