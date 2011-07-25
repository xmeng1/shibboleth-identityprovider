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

import java.security.Principal;

import javax.security.auth.Subject;

import org.joda.time.DateTime;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileHandler;
import edu.internet2.middleware.shibboleth.common.profile.ProfileHandlerManager;
import edu.internet2.middleware.shibboleth.common.profile.provider.AbstractShibbolethProfileHandler;
import edu.internet2.middleware.shibboleth.idp.authn.ShibbolethSSOLoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;
import edu.internet2.middleware.shibboleth.idp.session.AuthenticationMethodInformation;
import edu.internet2.middleware.shibboleth.idp.session.impl.AuthenticationMethodInformationImpl;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;

/**
 * Unit test for Shibboleth SSO requests.
 */
public class ShibbolethSSOTestCase extends BaseConf1TestCase {

    /** Tests initial leg of the SSO request where request is decoded and sent to the authentication engine. */
    public void testFirstAuthenticationLeg() throws Exception {
        MockServletContext servletContext = new MockServletContext();

        MockHttpServletRequest servletRequest = buildServletRequest();
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();

        ProfileHandlerManager handlerManager = (ProfileHandlerManager) getApplicationContext().getBean(
                "shibboleth.HandlerManager");
        AbstractShibbolethProfileHandler handler = (AbstractShibbolethProfileHandler) handlerManager
                .getProfileHandler(servletRequest);
        assertNotNull(handler);

        // Process request
        HTTPInTransport profileRequest = new HttpServletRequestAdapter(servletRequest);
        HTTPOutTransport profileResponse = new HttpServletResponseAdapter(servletResponse, false);
        handler.processRequest(profileRequest, profileResponse);

        servletRequest.setCookies(servletResponse.getCookies());
        ShibbolethSSOLoginContext loginContext = (ShibbolethSSOLoginContext) HttpServletHelper.getLoginContext(handler
                .getStorageService(), servletContext, servletRequest);

        assertNotNull(loginContext);
        assertEquals(false, loginContext.getAuthenticationAttempted());
        assertEquals(false, loginContext.isForceAuthRequired());
        assertEquals(false, loginContext.isPassiveAuthRequired());
        assertEquals("/AuthnEngine", loginContext.getAuthenticationEngineURL());
        assertEquals("/shibboleth/SSO", loginContext.getProfileHandlerURL());
        assertEquals("urn:example.org:sp1", loginContext.getRelyingPartyId());
        assertEquals(0, loginContext.getRequestedAuthenticationMethods().size());
        assertEquals("https://example.org/mySP", loginContext.getSpAssertionConsumerService());
        assertEquals("https://example.org/mySP", loginContext.getSpAssertionConsumerService());

        assertTrue(servletResponse.getRedirectedUrl().endsWith("/AuthnEngine"));
    }

    /** Tests second leg of the SSO request where request returns to SSO handler and AuthN statement is generated. */
    public void testSecondAuthenticationLeg() throws Exception {
        MockServletContext servletContext = new MockServletContext();
        MockHttpServletRequest servletRequest = buildServletRequest();
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();

        ProfileHandlerManager handlerManager = (ProfileHandlerManager) getApplicationContext().getBean(
                "shibboleth.HandlerManager");
        AbstractShibbolethProfileHandler handler = (AbstractShibbolethProfileHandler) handlerManager
                .getProfileHandler(servletRequest);
        assertNotNull(handler);

        HttpServletHelper.bindLoginContext(buildLoginContext(), handler.getStorageService(), servletContext,
                servletRequest, servletResponse);
        servletRequest.setCookies(servletResponse.getCookies());

        // Process request
        HTTPInTransport profileRequest = new HttpServletRequestAdapter(servletRequest);
        HTTPOutTransport profileResponse = new HttpServletResponseAdapter(servletResponse, false);
        handler.processRequest(profileRequest, profileResponse);

        String response = servletResponse.getContentAsString();
        assertTrue(response.contains("action=\"https&#x3a;&#x2f;&#x2f;example.org&#x2f;mySP\" method=\"post\""));
        assertTrue(response.contains("name=\"TARGET\" value=\"https&#x3a;&#x2f;&#x2f;example.org&#x2f;mySP\""));
        assertTrue(response.contains("SAMLResponse"));
    }

    /** Tests that the SSO handler correctly fails out if the Shib SSO profile is not configured. */
    public void testAuthenticationWithoutConfiguredSSO() {
        MockHttpServletRequest servletRequest = buildServletRequest();
        servletRequest.setParameter("providerId", "urn:example.org:BogusSP");

        MockHttpServletResponse servletResponse = new MockHttpServletResponse();

        ProfileHandlerManager handlerManager = (ProfileHandlerManager) getApplicationContext().getBean(
                "shibboleth.HandlerManager");
        ProfileHandler handler = handlerManager.getProfileHandler(servletRequest);
        assertNotNull(handler);

        // Process request
        HTTPInTransport profileRequest = new HttpServletRequestAdapter(servletRequest);
        HTTPOutTransport profileResponse = new HttpServletResponseAdapter(servletResponse, false);
        try {
            handler.processRequest(profileRequest, profileResponse);
            fail("Request processing expected to due to lack of configured Shib SSO profile");
        } catch (ProfileException e) {

        }
    }

    protected MockHttpServletRequest buildServletRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setPathInfo("/shibboleth/SSO");
        request.setParameter("providerId", "urn:example.org:sp1");
        request.setParameter("shire", "https://example.org/mySP");
        request.setParameter("target", "https://example.org/mySP");

        return request;
    }

    protected ShibbolethSSOLoginContext buildLoginContext() {
        Principal principal = new UsernamePrincipal("test");

        Subject subject = new Subject();
        subject.getPrincipals().add(principal);

        AuthenticationMethodInformation authnInfo = new AuthenticationMethodInformationImpl(subject, principal,
                "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified", new DateTime(), 3600);

        ShibbolethSSOLoginContext loginContext = new ShibbolethSSOLoginContext();
        loginContext.setAuthenticationMethodInformation(authnInfo);
        loginContext.setPrincipalAuthenticated(true);
        loginContext.setRelyingParty("urn:example.org:sp1");
        loginContext.setSpAssertionConsumerService("https://example.org/mySP");
        loginContext.setSpTarget("https://example.org/mySP");

        return loginContext;
    }
}