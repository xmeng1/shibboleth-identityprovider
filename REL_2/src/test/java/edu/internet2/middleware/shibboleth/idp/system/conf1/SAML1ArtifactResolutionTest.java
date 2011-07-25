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
import java.security.SecureRandom;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.common.binding.artifact.SAMLArtifactMap.SAMLArtifactMapEntry;
import org.opensaml.saml1.binding.artifact.SAML1ArtifactType0002;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.AssertionArtifact;
import org.opensaml.saml1.core.Request;
import org.opensaml.ws.soap.common.SOAPObjectBuilder;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.profile.ProfileHandler;
import edu.internet2.middleware.shibboleth.common.profile.ProfileHandlerManager;

/**
 * 
 */
public class SAML1ArtifactResolutionTest extends BaseConf1TestCase {

    public void testArtifactResolution() throws Exception {
        String relyingPartyId = "urn:example.org:sp1";
        SAMLArtifactMapEntry artifactEntry = stageArtifact(relyingPartyId);
        String soapMessage = buildRequestMessage(relyingPartyId, artifactEntry.getArtifact());

        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.setMethod("POST");
        servletRequest.setPathInfo("/saml1/SOAP/ArtifactResolution");
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
        assertTrue(response.contains("saml1:Assertion"));
    }
    
    public void testWithoutConfiguration() throws Exception {
        String relyingPartyId = "urn:example.org:BogusSP";
        SAMLArtifactMapEntry artifactEntry = stageArtifact(relyingPartyId);
        String soapMessage = buildRequestMessage(relyingPartyId, artifactEntry.getArtifact());

        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.setMethod("POST");
        servletRequest.setPathInfo("/saml1/SOAP/ArtifactResolution");
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
        assertTrue(response.contains("saml1p:RequestDenied"));
    }

    @SuppressWarnings("unchecked")
    protected SAMLArtifactMapEntry stageArtifact(String relyingPartyId) throws Exception {
        SAMLObjectBuilder<Assertion> assetionBuilder = (SAMLObjectBuilder<Assertion>) builderFactory
                .getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        Assertion assertion = assetionBuilder.buildObject();

        SecureRandom handleGenerator = SecureRandom.getInstance("SHA1PRNG");
        byte[] assertionHandle = new byte[20];
        handleGenerator.nextBytes(assertionHandle);
        SAML1ArtifactType0002 artifact = new SAML1ArtifactType0002(assertionHandle, relyingPartyId);

        SAMLArtifactMap artifactMap = (SAMLArtifactMap) getApplicationContext().getBean("shibboleth.ArtifactMap");
        artifactMap.put(artifact.base64Encode(), relyingPartyId, "urn:example.org:idp1", assertion);
        return artifactMap.get(artifact.base64Encode());
    }

    @SuppressWarnings("unchecked")
    protected String buildRequestMessage(String relyingPartyId, String artifact) throws Exception {
        SAMLObjectBuilder<AssertionArtifact> assertionArtifactBuilder = (SAMLObjectBuilder<AssertionArtifact>) builderFactory
                .getBuilder(AssertionArtifact.DEFAULT_ELEMENT_NAME);
        AssertionArtifact aa = assertionArtifactBuilder.buildObject();
        aa.setAssertionArtifact(artifact);

        SAMLObjectBuilder<Request> requestBuilder = (SAMLObjectBuilder<Request>) builderFactory
                .getBuilder(Request.DEFAULT_ELEMENT_NAME);
        Request request = requestBuilder.buildObject();
        request.setID("1");
        request.setIssueInstant(new DateTime());
        request.getAssertionArtifacts().add(aa);

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