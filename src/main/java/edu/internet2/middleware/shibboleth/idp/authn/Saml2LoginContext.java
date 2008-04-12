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

package edu.internet2.middleware.shibboleth.idp.authn;

import java.io.Serializable;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

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
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

/**
 * A SAML 2.0 {@link LoginContext}.
 * 
 * This class can interpret {@link RequestedAuthnContext} and act accordingly.
 */
public class Saml2LoginContext extends LoginContext implements Serializable {

    /** Serial version UID. */
    private static final long serialVersionUID = -2518779446947534977L;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(Saml2LoginContext.class);
    
    /** Relay state from authentication request. */
    private String relayState;

    /** Serialized authentication request. */
    private String serialAuthnRequest;

    /** Unmarshalled authentication request. */
    private transient AuthnRequest authnRequest;

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
        
        setForceAuthRequired(authnRequest.isForceAuthn());
        setPassiveAuthRequired(authnRequest.isPassive());
        getRequestedAuthenticationMethods().addAll(extractRequestedAuthenticationMethods());
    }

    /**
     * Gets the authentication request that started the login process.
     * 
     * @return authentication request that started the login process
     * 
     * @throws UnmarshallingException thrown if the serialized form on the authentication request can be unmarshalled
     */
    public AuthnRequest getAuthenticationRequest() throws UnmarshallingException {
        if (authnRequest == null) {
            authnRequest = deserializeRequest(serialAuthnRequest);
        }

        return authnRequest;
    }
    
    /**
     * Gets the relay state from the orginating authentication request.
     * 
     * @return relay state from the orginating authentication request
     */
    public String getRelayState(){
        return relayState;
    }

    /**
     * Gets the requested authentication context information from the authentication request.
     * 
     * @return requested authentication context information or null
     */
    public RequestedAuthnContext getRequestedAuthenticationContext() {
        try {
            AuthnRequest request = getAuthenticationRequest();
            return request.getRequestedAuthnContext();
        } catch (UnmarshallingException e) {
            return null;
        }
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
     * Deserailizes an authentication request from a string.
     * 
     * @param request request to deserialize
     * 
     * @return the request XMLObject
     * 
     * @throws UnmarshallingException thrown if the request can no be deserialized and unmarshalled
     */
    protected AuthnRequest deserializeRequest(String request) throws UnmarshallingException {
        DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
        try {
            DocumentBuilder docBuilder = builderFactory.newDocumentBuilder();
            InputSource requestInput = new InputSource(new StringReader(request));
            Element requestElem = docBuilder.parse(requestInput).getDocumentElement();
            Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(requestElem);
            return (AuthnRequest) unmarshaller.unmarshall(requestElem);
        } catch (Exception e) {
            throw new UnmarshallingException("Unable to read serialized authentication request");
        }
    }
    
    /**
     * Extracts the authentication methods requested within the request.
     * 
     * @return requested authentication methods, or an empty list if no preference
     */
    protected List<String> extractRequestedAuthenticationMethods(){
        ArrayList<String> requestedMethods = new ArrayList<String>();

        RequestedAuthnContext authnContext = getRequestedAuthenticationContext();
        if (authnContext == null) {
            return requestedMethods;
        }

        // For the immediate future, we only support the "exact" comparator.
        AuthnContextComparisonTypeEnumeration comparator = authnContext.getComparison();
        if (comparator != null && comparator != AuthnContextComparisonTypeEnumeration.EXACT) {
            log.error("Unsupported comparision operator ( " + comparator
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
                if (declRef != null&& !DatatypeHelper.isEmpty(declRef.getAuthnContextDeclRef())) {
                    requestedMethods.add(declRef.getAuthnContextDeclRef());
                }
            }
        }
        
        if(requestedMethods.contains(AuthnContext.UNSPECIFIED_AUTHN_CTX)){
            requestedMethods.clear();
        }

        return requestedMethods;
    }
}