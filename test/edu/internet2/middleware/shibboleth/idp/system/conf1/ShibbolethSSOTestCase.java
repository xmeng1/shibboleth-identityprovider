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
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileHandler;
import edu.internet2.middleware.shibboleth.common.profile.ProfileHandlerManager;
import edu.internet2.middleware.shibboleth.idp.authn.ShibbolethSSOLoginContext;

/**
 * Unit test for Shibboleth SSO requests.
 */
public class ShibbolethSSOTestCase extends BaseConf1TestCase {

    /** Tests initial leg of the SSO request where request is decoded and sent to the authentication engine. */
    public void testFirstAuthenticationLeg() throws Exception {
        MockHttpServletRequest servletRequest = buildServletRequest();
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();

        ProfileHandlerManager handlerManager = (ProfileHandlerManager) getApplicationContext().getBean(
                "shibboleth.HandlerManager");
        ProfileHandler handler = handlerManager.getProfileHandler(servletRequest);
        assertNotNull(handler);

        // Process request
        HTTPInTransport profileRequest = new HttpServletRequestAdapter(servletRequest);
        HTTPOutTransport profileResponse = new HttpServletResponseAdapter(servletResponse, false);
        handler.processRequest(profileRequest, profileResponse);

        HttpSession session = servletRequest.getSession();
        ShibbolethSSOLoginContext loginContext = (ShibbolethSSOLoginContext) session
                .getAttribute(ShibbolethSSOLoginContext.LOGIN_CONTEXT_KEY);

        assertNotNull(loginContext);
        assertEquals(false, loginContext.getAuthenticationAttempted());
        assertEquals(false, loginContext.isForceAuthRequired());
        assertEquals(false, loginContext.isPassiveAuthRequired());
        assertEquals("/AuthnEngine", loginContext.getAuthenticationEngineURL());
        assertEquals("/shibboleth/SSO", loginContext.getProfileHandlerURL());
        assertEquals("urn:example.org:sp1", loginContext.getRelyingPartyId());
        assertEquals(0, loginContext.getRequestedAuthenticationMethods().size());
        assertEquals("https://example.org/mySP", loginContext.getSpAssertionConsumerService());
        assertEquals("https://example.org/mySP", loginContext.getSpTarget());

        assertEquals("/AuthnEngine", servletResponse.getForwardedUrl());
    }

    /** Tests second leg of the SSO request where request returns to SSO handler and AuthN statement is generated. */
    public void testSecondAuthenticationLeg() throws Exception {
        MockHttpServletRequest servletRequest = buildServletRequest();
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();

        HttpSession httpSession = servletRequest.getSession(true);
        httpSession.setAttribute(ShibbolethSSOLoginContext.LOGIN_CONTEXT_KEY, buildLoginContext());

        ProfileHandlerManager handlerManager = (ProfileHandlerManager) getApplicationContext().getBean(
                "shibboleth.HandlerManager");
        ProfileHandler handler = handlerManager.getProfileHandler(servletRequest);
        assertNotNull(handler);

        // Process request
        HTTPInTransport profileRequest = new HttpServletRequestAdapter(servletRequest);
        HTTPOutTransport profileResponse = new HttpServletResponseAdapter(servletResponse, false);
        handler.processRequest(profileRequest, profileResponse);

        String response = servletResponse.getContentAsString();
        assertTrue(response.contains("action=\"https://example.org/mySP\" method=\"post\""));
        assertTrue(response.contains("name=\"TARGET\" value=\"https://example.org/mySP\""));
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
        ShibbolethSSOLoginContext loginContext = new ShibbolethSSOLoginContext();
        loginContext.setAuthenticationInstant(new DateTime());
        loginContext.setAuthenticationMethod("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified");
        loginContext.setPrincipalAuthenticated(true);
        loginContext.setPrincipalName("testUser");
        loginContext.setRelyingParty("urn:example.org:sp1");
        loginContext.setSpAssertionConsumerService("https://example.org/mySP");
        loginContext.setSpTarget("https://example.org/mySP");

        return loginContext;
    }
}