/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.idp.authn;

import java.io.Serializable;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.List;

import org.opensaml.Configuration;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnContextDeclRef;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.LazyList;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * A SAML 2.0 {@link LoginContext}.
 * 
 * This class can interpret {@link RequestedAuthnContext} and act accordingly.
 */
public class Saml2LoginContext extends LoginContext implements Serializable {

    /** Serial version UID. */
    private static final long serialVersionUID = -7117092606828289070L;

    /** Relay state from authentication request. */
    private String relayState;

    /** The authentication request. */
    private transient AuthnRequest authnRequest;

    /** Serialized authentication request. */
    private String serialAuthnRequest;

    /** Unsolicited SSO indicator. */
    private boolean unsolicited;

    /**
     * Creates a new instance of Saml2LoginContext.
     * 
     * @param relyingParty entity ID of the relying party
     * @param state relay state from incoming authentication request
     * @param request SAML 2.0 Authentication Request
     * 
     * @throws MarshallingException thrown if the given request can not be marshalled and serialized into a string
     */
    public Saml2LoginContext(String relyingParty, String state, AuthnRequest request) throws MarshallingException {
        super();

        if (relyingParty == null || request == null) {
            throw new IllegalArgumentException("SAML 2 authentication request and relying party ID may not be null");
        }
        
        setRelyingParty(relyingParty);
        relayState = state;
        authnRequest = request;
        serialAuthnRequest = serializeRequest(request);

        setForceAuthRequired(request.isForceAuthn());
        setPassiveAuthRequired(request.isPassive());
        getRequestedAuthenticationMethods().addAll(extractRequestedAuthenticationMethods(request));
    }

    /**
     * Gets the authentication request object.
     * 
     * @return the authentication request object
     * 
     * @throws UnmarshallingException thrown if there is a problem unmarshalling the serialized form of the request
     */
    public synchronized AuthnRequest getAuthenticiationRequestXmlObject() throws UnmarshallingException {
        if (authnRequest == null) {
            try {
                ParserPool parser = Configuration.getParserPool();
                Document requestDoc = parser.parse(new StringReader(serialAuthnRequest));
                Unmarshaller requestUnmarshaller =
                        Configuration.getUnmarshallerFactory().getUnmarshaller(AuthnRequest.TYPE_NAME);
                authnRequest = (AuthnRequest) requestUnmarshaller.unmarshall(requestDoc.getDocumentElement());
            } catch (XMLParserException e) {
                throw new UnmarshallingException("Unable to unmarshall serialized authentication request", e);
            }
        }

        return authnRequest;
    }

    /**
     * Gets the serialized authentication request that started the login process.
     * 
     * @return authentication request that started the login process
     * 
     * @throws UnmarshallingException thrown if the serialized form on the authentication request can be unmarshalled
     */
    public String getAuthenticationRequest() throws UnmarshallingException {
        return serialAuthnRequest;
    }

    /**
     * Gets the relay state from the originating authentication request.
     * 
     * @return relay state from the originating authentication request
     */
    public synchronized String getRelayState() {
        return relayState;
    }

    /**
     * Returns the unsolicited SSO indicator.
     * 
     * @return the unsolicited SSO indicator
     */
    public boolean isUnsolicited() {
        return unsolicited;
    }

    /**
     * Sets the unsolicited SSO indicator.
     * 
     * @param isUnsolicited unsolicited SSO indicator to set
     */
    public void setUnsolicited(boolean isUnsolicited) {
        unsolicited = isUnsolicited;
    }

    /**
     * Serializes an authentication request into a string.
     * 
     * @param request the request to serialize
     * 
     * @return the serialized form of the string
     * 
     * @throws MarshallingException thrown if the request can not be marshalled and serialized
     */
    protected String serializeRequest(AuthnRequest request) throws MarshallingException {
        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(request);
        Element requestElem = marshaller.marshall(request);
        StringWriter writer = new StringWriter();
        XMLHelper.writeNode(requestElem, writer);
        return writer.toString();
    }

    /**
     * Extracts the authentication methods requested within the request.
     * 
     * @param request the authentication request
     * 
     * @return requested authentication methods, or an empty list if no preference
     */
    protected List<String> extractRequestedAuthenticationMethods(AuthnRequest request) {
        LazyList<String> requestedMethods = new LazyList<String>();

        RequestedAuthnContext authnContext = request.getRequestedAuthnContext();
        if (authnContext == null) {
            return requestedMethods;
        }

        // For the immediate future, we only support the "exact" comparator.
        AuthnContextComparisonTypeEnumeration comparator = authnContext.getComparison();
        if (comparator != null && comparator != AuthnContextComparisonTypeEnumeration.EXACT) {
            Logger log = LoggerFactory.getLogger(Saml2LoginContext.class);
            log.warn("Unsupported comparision operator ( " + comparator
                    + ") in RequestedAuthnContext. Only exact comparisions are supported.");
            return requestedMethods;
        }

        // build a list of all requested authn classes and declrefs
        List<AuthnContextClassRef> authnClasses = authnContext.getAuthnContextClassRefs();
        if (authnClasses != null) {
            for (AuthnContextClassRef classRef : authnClasses) {
                if (classRef != null && !DatatypeHelper.isEmpty(classRef.getAuthnContextClassRef())) {
                    requestedMethods.add(classRef.getAuthnContextClassRef());
                }
            }
        }

        List<AuthnContextDeclRef> authnDeclRefs = authnContext.getAuthnContextDeclRefs();
        if (authnDeclRefs != null) {
            for (AuthnContextDeclRef declRef : authnDeclRefs) {
                if (declRef != null && !DatatypeHelper.isEmpty(declRef.getAuthnContextDeclRef())) {
                    requestedMethods.add(declRef.getAuthnContextDeclRef());
                }
            }
        }

        if (requestedMethods.contains(AuthnContext.UNSPECIFIED_AUTHN_CTX)) {
            requestedMethods.clear();
        }

        return requestedMethods;
    }
}