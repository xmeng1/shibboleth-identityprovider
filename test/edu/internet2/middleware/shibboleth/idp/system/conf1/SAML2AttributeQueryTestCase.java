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

package edu.internet2.middleware.shibboleth.idp.system.conf1;

import java.io.StringWriter;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.StatusCode;
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

    /** Tests a request where the Issuer can not be authenticated. */
    public void testUnathenticatedIssuer() throws Exception {
        AttributeQuery query = buildAttributeQuery("urn:example.org:unitTest:sp1");
        String soapMessage = getSOAPMessage(query);

        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.setPathInfo("/IdP/saml2/SOAP/AttributeQuery");
        servletRequest.setContent(soapMessage.getBytes());

        MockHttpServletResponse servletResponse = new MockHttpServletResponse();

        ProfileHandlerManager handlerManager = (ProfileHandlerManager) getApplicationContext().getBean(
                "shibboleth.HandlerManager");
        ProfileHandler handler = handlerManager.getProfileHandler(servletRequest);
        assertNotNull(handler);

        // Process request
        HTTPInTransport profileRequest = new HttpServletRequestAdapter(servletRequest);
        HTTPOutTransport profileResponse = new HttpServletResponseAdapter(servletResponse);
        handler.processRequest(profileRequest, profileResponse);

        String response = servletResponse.getContentAsString();
        assertTrue(response.contains(StatusCode.RESPONDER_URI));
        assertTrue(response.contains(StatusCode.REQUEST_DENIED_URI));
    }

    /** Test a request where the Issuer is authenticated and has not requested any specific attributes. */
    public void testAuthenticatedIssuerNoProfileConfiguration() throws Exception {
        AttributeQuery query = buildAttributeQuery("urn:example.org:unitTest:sp1");
        String soapMessage = getSOAPMessage(query);

        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.setPathInfo("/IdP/saml2/SOAP/AttributeQueryNoAuth");
        servletRequest.setContent(soapMessage.getBytes());

        MockHttpServletResponse servletResponse = new MockHttpServletResponse();

        ProfileHandlerManager handlerManager = (ProfileHandlerManager) getApplicationContext().getBean(
                "shibboleth.HandlerManager");
        ProfileHandler handler = handlerManager.getProfileHandler(servletRequest);
        assertNotNull(handler);

        // Process request
        HTTPInTransport profileRequest = new HttpServletRequestAdapter(servletRequest);
        HTTPOutTransport profileResponse = new HttpServletResponseAdapter(servletResponse);
        handler.processRequest(profileRequest, profileResponse);

        String response = servletResponse.getContentAsString();
        assertTrue(response.contains(StatusCode.RESPONDER_URI));
        assertTrue(response.contains(StatusCode.REQUEST_DENIED_URI));
    }

    /** Test a request where the Issuer is authenticated and has not requested any specific attributes. */
    public void testAuthenticatedIssuerNoRequestAttributes() throws Exception {
        AttributeQuery query = buildAttributeQuery("urn:example.org:unitTestFed:sp2");
        String soapMessage = getSOAPMessage(query);

        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.setPathInfo("/IdP/saml2/SOAP/AttributeQueryNoAuth");
        servletRequest.setContent(soapMessage.getBytes());

        MockHttpServletResponse servletResponse = new MockHttpServletResponse();

        ProfileHandlerManager handlerManager = (ProfileHandlerManager) getApplicationContext().getBean(
                "shibboleth.HandlerManager");
        ProfileHandler handler = handlerManager.getProfileHandler(servletRequest);
        assertNotNull(handler);

        // Process request
        HTTPInTransport profileRequest = new HttpServletRequestAdapter(servletRequest);
        HTTPOutTransport profileResponse = new HttpServletResponseAdapter(servletResponse);
        handler.processRequest(profileRequest, profileResponse);

        String response = servletResponse.getContentAsString();
        assertTrue(response.contains(StatusCode.SUCCESS_URI));
        assertTrue(response.contains("Name=\"cn\""));
        assertTrue(response.contains("Name=\"uid\""));
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