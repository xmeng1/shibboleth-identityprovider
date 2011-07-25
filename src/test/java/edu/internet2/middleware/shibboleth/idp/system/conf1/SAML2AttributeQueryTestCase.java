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
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
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
 * A system test that meant to simulate various types of SAML 2 attribute queries.
 */
public class SAML2AttributeQueryTestCase extends BaseConf1TestCase {

    /** Tests that the attribute query handler correctly handles an incomming query. */
    public void testAttributeQuery() throws Exception{
        AttributeQuery query = buildAttributeQuery("urn:example.org:sp1");
        String soapMessage = getSOAPMessage(query);

        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.setMethod("POST");
        servletRequest.setPathInfo("/saml2/SOAP/AttributeQuery");
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
        assertTrue(response.contains("urn:oasis:names:tc:SAML:2.0:status:Success"));
        assertTrue(response.contains(" Name=\"urn:oid:1.3.6.1.4.1.5923.1.1.1.7\""));
        assertTrue(response.contains("urn:example.org:entitlement:entitlement1"));
    }
    
    /** Tests that the attribute query handler correctly fails out if the profile is not configured. */
    public void testAuthenticationWithoutConfiguredQuery() throws Exception{
        AttributeQuery query = buildAttributeQuery("urn:example.org:BogusSP");
        String soapMessage = getSOAPMessage(query);

        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.setMethod("POST");
        servletRequest.setPathInfo("/saml2/SOAP/AttributeQuery");
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
        assertTrue(response.contains("urn:oasis:names:tc:SAML:2.0:status:Responder"));
        assertTrue(response.contains("urn:oasis:names:tc:SAML:2.0:status:RequestDenied"));
    }

    /**
     * Builds a basic attribute query.
     * 
     * @return basic attribute query
     */
    @SuppressWarnings("unchecked")
    protected AttributeQuery buildAttributeQuery(String requester) {
        SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
                .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(requester);

        SAMLObjectBuilder<NameID> nameIdBuilder = (SAMLObjectBuilder<NameID>) builderFactory
                .getBuilder(NameID.DEFAULT_ELEMENT_NAME);
        NameID nameId = nameIdBuilder.buildObject();
        nameId.setValue("testUser");
        nameId.setFormat(NameID.UNSPECIFIED);

        SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) builderFactory
                .getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        Subject subject = subjectBuilder.buildObject();
        subject.setNameID(nameId);

        SAMLObjectBuilder<AttributeQuery> attributeQueryBuilder = (SAMLObjectBuilder<AttributeQuery>) builderFactory
                .getBuilder(AttributeQuery.DEFAULT_ELEMENT_NAME);
        AttributeQuery query = attributeQueryBuilder.buildObject();
        query.setID("1");
        query.setIssueInstant(new DateTime());
        query.setIssuer(issuer);
        query.setSubject(subject);
        query.setVersion(SAMLVersion.VERSION_20);

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
        SOAPObjectBuilder<Body> bodyBuilder = (SOAPObjectBuilder<Body>) builderFactory
                .getBuilder(Body.DEFAULT_ELEMENT_NAME);
        Body body = bodyBuilder.buildObject();
        body.getUnknownXMLObjects().add(query);

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