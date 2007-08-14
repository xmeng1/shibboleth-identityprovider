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

import javax.servlet.http.HttpSession;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileHandler;
import edu.internet2.middleware.shibboleth.common.profile.ProfileHandlerManager;
import edu.internet2.middleware.shibboleth.idp.authn.Saml2LoginContext;

/**
 * 
 */
public class SAML2SSOTestCase extends BaseConf1TestCase {

    /** Tests a request where the Issuer can not be authenticated. */
    public void testUnathenticatedIssuer() throws Exception {
        AuthnRequest authnRequest = buildAuthnRequest("urn:example.org:unitTest:sp1");
        String authnRequestString = getSamlRequestString(authnRequest);

        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.setPathInfo("/IdP/saml2/SSONoAuth");
        servletRequest.setParameter("SAMLRequest", Base64.encodeBytes(authnRequestString.getBytes()));

        MockHttpServletResponse servletResponse = new MockHttpServletResponse();

        ProfileHandlerManager handlerManager = (ProfileHandlerManager) getApplicationContext().getBean(
                "shibboleth.HandlerManager");
        ProfileHandler handler = handlerManager.getProfileHandler(servletRequest);
        assertNotNull(handler);

        // Process request
        HTTPInTransport profileRequest = new HttpServletRequestAdapter(servletRequest);
        HTTPOutTransport profileResponse = new HttpServletResponseAdapter(servletResponse);

        try {
            handler.processRequest(profileRequest, profileResponse);
            fail();
        } catch (ProfileException e) {
            // expected
        }
    }

    public void testAuthenicatedIssuer() throws Exception {
        AuthnRequest authnRequest = buildAuthnRequest("urn:example.org:unitTestFed:sp2");
        String authnRequestString = getSamlRequestString(authnRequest);

        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.setPathInfo("/IdP/saml2/SSONoAuth");
        servletRequest.setParameter("SAMLRequest", Base64.encodeBytes(authnRequestString.getBytes()));

        MockHttpServletResponse servletResponse = new MockHttpServletResponse();

        ProfileHandlerManager handlerManager = (ProfileHandlerManager) getApplicationContext().getBean(
                "shibboleth.HandlerManager");
        ProfileHandler handler = handlerManager.getProfileHandler(servletRequest);
        assertNotNull(handler);

        // Process request
        HTTPInTransport profileRequest = new HttpServletRequestAdapter(servletRequest);
        HTTPOutTransport profileResponse = new HttpServletResponseAdapter(servletResponse);
        handler.processRequest(profileRequest, profileResponse);

        HttpSession session = servletRequest.getSession();
        Saml2LoginContext loginContext = (Saml2LoginContext) session.getAttribute(Saml2LoginContext.LOGIN_CONTEXT_KEY);
        assertNotNull(loginContext);
    }

    public void testSecondLeg() throws Exception {
        AuthnRequest authnRequest = buildAuthnRequest("urn:example.org:unitTestFed:sp2");

        Saml2LoginContext loginContext = new Saml2LoginContext("urn:example.org:unitTestFed:sp2", null, authnRequest);
        loginContext.setAuthenticationInstant(new DateTime());
        loginContext.setAuthenticationMethod("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified");
        loginContext.setPrincipalAuthenticated(true);
        loginContext.setPrincipalName("testUser");

        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.setPathInfo("/IdP/saml2/SSONoAuth");

        HttpSession session = servletRequest.getSession();
        session.setAttribute(Saml2LoginContext.LOGIN_CONTEXT_KEY, loginContext);

        MockHttpServletResponse servletResponse = new MockHttpServletResponse();

        ProfileHandlerManager handlerManager = (ProfileHandlerManager) getApplicationContext().getBean(
                "shibboleth.HandlerManager");
        ProfileHandler handler = handlerManager.getProfileHandler(servletRequest);
        assertNotNull(handler);

        // Process request
        HTTPInTransport profileRequest = new HttpServletRequestAdapter(servletRequest);
        HTTPOutTransport profileResponse = new HttpServletResponseAdapter(servletResponse);
        handler.processRequest(profileRequest, profileResponse);

        System.out.println(servletResponse.getContentAsString());
    }

    protected AuthnRequest buildAuthnRequest(String requester) {
        SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
                .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(requester);

        SAMLObjectBuilder<AuthnRequest> authnRequestBuilder = (SAMLObjectBuilder<AuthnRequest>) builderFactory
                .getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
        AuthnRequest request = authnRequestBuilder.buildObject();
        request.setID("1");
        request.setIssueInstant(new DateTime());
        request.setIssuer(issuer);

        return request;
    }

    protected String getSamlRequestString(AuthnRequest request) throws MarshallingException {
        Marshaller marshaller = marshallerFactory.getMarshaller(request);
        Element requestElem = marshaller.marshall(request);
        return XMLHelper.nodeToString(requestElem);
    }
}