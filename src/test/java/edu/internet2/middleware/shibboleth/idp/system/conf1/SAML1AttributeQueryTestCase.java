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

package edu.internet2.middleware.shibboleth.idp.system.conf1;

import java.io.StringWriter;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml1.core.AttributeQuery;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml1.core.Request;
import org.opensaml.saml1.core.Subject;
import org.opensaml.ws.soap.common.SOAPObjectBuilder;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.profile.ProfileHandler;
import edu.internet2.middleware.shibboleth.common.profile.ProfileHandlerManager;

/**
 * Unit test for the SAML 1 attribute query flow.
 */
public class SAML1AttributeQueryTestCase extends BaseConf1TestCase {
    
    /** Tests that the attribute query handler correctly handles an incomming query. */
    public void testAttributeQuery() throws Exception{
        AttributeQuery query = buildAttributeQuery("urn:example.org:sp1");
        String soapMessage = getSOAPMessage(query);

        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.setMethod("POST");
        servletRequest.setPathInfo("/saml1/SOAP/AttributeQuery");
        servletRequest.setContent(soapMessage.getBytes());

        MockHttpServletResponse servletResponse = new MockHttpServletResponse();

        ProfileHandlerManager handlerManager = (ProfileHandlerManager) getApplicationContext().getBean(
                "shibboleth.HandlerManager");
        ProfileHandler handler = handlerManager.getProfileHandler(servletRequest);
        assertNotNull(handler);

        // Process request
        HTTPInTransport profileRequest = new HttpServletRequestAdapter(servletRequest);
        HTTPOutTransport profileResponse = new HttpServletResponseAdapter(servletResponse, false);
        handler.processRequest(profileRequest, profileResponse);

        String response = servletResponse.getContentAsString();
        assertTrue(response.contains("saml1p:Success"));
        assertTrue(response.contains("AttributeName=\"urn:mace:dir:attribute-def:eduPersonEntitlement\""));
        assertTrue(response.contains("urn:example.org:entitlement:entitlement1"));
    }
    
    /** Tests that the attribute query handler correctly fails out if the profile is not configured. */
    public void testAuthenticationWithoutConfiguredQuery() throws Exception{
        AttributeQuery query = buildAttributeQuery("urn:example.org:BogusSP");
        String soapMessage = getSOAPMessage(query);

        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.setMethod("POST");
        servletRequest.setPathInfo("/saml1/SOAP/AttributeQuery");
        servletRequest.setContent(soapMessage.getBytes());

        MockHttpServletResponse servletResponse = new MockHttpServletResponse();

        ProfileHandlerManager handlerManager = (ProfileHandlerManager) getApplicationContext().getBean(
                "shibboleth.HandlerManager");
        ProfileHandler handler = handlerManager.getProfileHandler(servletRequest);
        assertNotNull(handler);

        // Process request
        HTTPInTransport profileRequest = new HttpServletRequestAdapter(servletRequest);
        HTTPOutTransport profileResponse = new HttpServletResponseAdapter(servletResponse, false);
        handler.processRequest(profileRequest, profileResponse);
            
        String response = servletResponse.getContentAsString();
        assertTrue(response.contains("saml1p:Responder"));
        assertTrue(response.contains("saml1p:RequestDenied"));
    }

    /**
     * Builds a basic attribute query.
     * 
     * @param relyingPartyId ID of the relying party that issued the assertion
     * 
     * @return basic attribute query
     */
    @SuppressWarnings("unchecked")
    protected AttributeQuery buildAttributeQuery(String relyingPartyId) {
        SAMLObjectBuilder<NameIdentifier> nameIdBuilder = (SAMLObjectBuilder<NameIdentifier>) builderFactory
                .getBuilder(NameIdentifier.DEFAULT_ELEMENT_NAME);
        NameIdentifier nameId = nameIdBuilder.buildObject();
        nameId.setNameIdentifier("testUser");
        nameId.setFormat(NameIdentifier.UNSPECIFIED);

        SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) builderFactory
                .getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        Subject subject = subjectBuilder.buildObject();
        subject.setNameIdentifier(nameId);

        SAMLObjectBuilder<AttributeQuery> attributeQueryBuilder = (SAMLObjectBuilder<AttributeQuery>) builderFactory
                .getBuilder(AttributeQuery.DEFAULT_ELEMENT_NAME);
        AttributeQuery query = attributeQueryBuilder.buildObject();
        query.setResource(relyingPartyId);
        query.setSubject(subject);

        return query;
    }

    /**
     * Wraps an attribute query in a SOAP message, marshalls, and serializes it.
     * 
     * @param query the attribute query to wrap
     * 
     * @return the SOAP message
     * 
     * @throws MarshallingException thrown if the message can not be marshalled
     */
    @SuppressWarnings("unchecked")
    protected String getSOAPMessage(AttributeQuery query) throws MarshallingException {
        SAMLObjectBuilder<Request> requestBuilder = (SAMLObjectBuilder<Request>)builderFactory.getBuilder(Request.DEFAULT_ELEMENT_NAME);
        Request request = requestBuilder.buildObject();
        request.setQuery(query);
        request.setIssueInstant(new DateTime());
        request.setID("1");
        
        SOAPObjectBuilder<Body> bodyBuilder = (SOAPObjectBuilder<Body>) builderFactory
                .getBuilder(Body.DEFAULT_ELEMENT_NAME);
        Body body = bodyBuilder.buildObject();
        body.getUnknownXMLObjects().add(request);

        SOAPObjectBuilder<Envelope> envelopeBuilder = (SOAPObjectBuilder<Envelope>) builderFactory
                .getBuilder(Envelope.DEFAULT_ELEMENT_NAME);
        Envelope envelope = envelopeBuilder.buildObject();
        envelope.setBody(body);

        Marshaller marshaller = marshallerFactory.getMarshaller(envelope);
        Element envelopeElem = marshaller.marshall(envelope);

        StringWriter writer = new StringWriter();
        XMLHelper.writeNode(envelopeElem, writer);
        return writer.toString();
    }
}