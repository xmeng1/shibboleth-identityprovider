/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
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

package edu.internet2.middleware.shibboleth.integration;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import junit.framework.TestCase;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Level;
import org.opensaml.SAMLException;

import com.mockrunner.mock.web.MockHttpServletResponse;

import edu.internet2.middleware.shibboleth.idp.provider.ShibbolethV1SSOHandler;
import edu.internet2.middleware.shibboleth.resource.AuthenticationFilter;
import edu.internet2.middleware.shibboleth.resource.FilterSupport.NewSessionData;
import edu.internet2.middleware.shibboleth.runner.ShibbolethRunner;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderConfig;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderContext;
import edu.internet2.middleware.shibboleth.serviceprovider.Session;

/**
 * A JUnit test case that POSTs the Assertion to the Filter
 * instead of the SP. The Filter then forwards the POST data
 * to the SP to create the Session.
 * @author Howard Gilbert
 */
public class FilterConsumerTest extends TestCase {
    
    // Create some constants, both as parameters and to test responses
    private static final String GIVENNAME = "Bozo";
    public static final String SURNAME = "Clown";
    private static final String TITLE = "clown";
    public static final String AFFILIATION = "member";
    public static final String SP_ENTITY = "https://sp.example.org/shibboleth";
    public static final String POST_HANDLER = "https://sp.example.org:9443/secure/Shibboleth.sso/SAML/POST";
    public static final String ARTIFACT_HANDER = "https://sp.example.org:9443/secure/Shibboleth.sso/SAML/Artifact";
    public static final String POST_SHIRE = "https://sp.example.org/shibboleth-sp/Shibboleth.sso/SAML/POST";
    public static final String ARTIFACT_SHIRE = "https://sp.example.org/shibboleth-sp/Shibboleth.sso/SAML/Artifact";
    public static final String TARGET = "https://nonsense";
    public static final String NETID = "BozoTClown";
    public static final String APPLICATIONID = "default";
    
    ShibbolethRunner runner;
    ShibbolethRunner.IdpTestContext idp;
    ShibbolethRunner.SPTestContext consumer;
    ShibbolethRunner.AuthenticationFilterContext filter;
    private NewSessionData newSessionData = new NewSessionData();
    ServiceProviderContext context;
    ServiceProviderConfig config;
    
    
    /**
     * TestCase setUp
     */
    protected void setUp() throws Exception {
        super.setUp();

        // Static call to set Log4J appenders and levels
        ShibbolethRunner.loglevel = Level.DEBUG;
        ShibbolethRunner.setupLogging();
        
        // Create the overall testing framework
        runner = new ShibbolethRunner();
        
        // Initialize the Idp, create the Mockrunner
        // objects to do SSO, AA, and Artifact calls, and
        // configure SAML to use the MockHTTPBindingProvider
        runner.setIdpConfigFileName("/basicIdpHome/idpconfig.xml"); 
        idp = runner.getIdp();
        
        // Initialize the SP with the default config file.
        runner.setSpConfigFileName("/basicSpHome/spconfig.xml"); 
        
        // Use one of two forms to initialize the SP
        // Only calling AssertionConsumerServlet.createSessionFromData
            //runner.initializeSP(); 
        // Using either MockRunner or direct call to SP
            consumer = ShibbolethRunner.consumer = runner.new SPTestContext();
        
        context=ServiceProviderContext.getInstance();
        config = context.getServiceProviderConfig();
        
        // Initialize the Filter and create its separate
        // Mockrunner simulated context. 
        filter= runner.getFilter();
            // Note: If you are going to change the Filter init-param
            // values, do it here before calling setUp()
        filter.setUp();
  
        newSessionData.applicationId=APPLICATIONID;
        newSessionData.providerId=SP_ENTITY;
          
        
        // Create the static collection of Attributes that are 
        // returned by the IdP for every principal.
        // This could be done in each test, just as long as it
        // is done before the SSO.
        Attributes attributes = runner.getAttributesCollection();
        attributes.put(new BasicAttribute("eduPersonAffiliation", AFFILIATION));
        // scoped
        attributes.put(new BasicAttribute("eduPersonScopedAffiliation", AFFILIATION));
        attributes.put(new BasicAttribute("title", TITLE));
        attributes.put(new BasicAttribute("givenName", GIVENNAME));
        attributes.put(new BasicAttribute("surname", SURNAME));
        // not in AAP
        attributes.put(new BasicAttribute("unacceptable","nonsense"));
        // not in ARP
        attributes.put(new BasicAttribute("unreleasable","foolishness"));
    }
    
    
    /**
     * Verify correct operation of Filter and wrapped Request object,
     * including attributes and headers.
     */
    private void checkFilter() {
        // Get the Request Wrapper object created by the Filter
        HttpServletRequest filteredRequest = 
            (HttpServletRequest) filter.testModule.getFilteredRequest();
        
        assertEquals(NETID,filteredRequest.getRemoteUser());
        assertEquals(NETID,filteredRequest.getHeader("REMOTE_USER"));
        assertEquals(SURNAME,filteredRequest.getHeader("Shib-Person-surname"));
        assertEquals(GIVENNAME,filteredRequest.getHeader("Shib-InetOrgPerson-givenName"));
        assertEquals(TITLE,filteredRequest.getHeader("Shib-OrgPerson-title"));
        
        Map attributes = (Map) filteredRequest.getAttribute(AuthenticationFilter.SHIB_ATTRIBUTES_PREFIX);
        Iterator iterator = attributes.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry entry = (Map.Entry) iterator.next();
            String key = (String) entry.getKey();
            String value = (String) entry.getValue();
            System.out.println(key+" : "+value);
        }
        
        
        Enumeration headerNames = filteredRequest.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String name = (String) headerNames.nextElement();
            String value = (String) filteredRequest.getHeader(name);
            System.out.println(name+ " : "+value );
        }
    }
    
    /**
     * Add Session object checking here.
     */
    private void checkSession(Session session) {
        assertNotNull(session);
        assertEquals(APPLICATIONID,session.getApplicationId());
        
        
        
    }
    
    /**
     * Test the Post Profile with Attribute Query
     * <p>Run SSO, Run AssertionConsumerServlet, then Run Filter</p>
     */
    public void testAttributeQuery() throws SAMLException {
        
        // Set the URL suffix that triggers SSO processing
        idp.resetRequest("SSO");
        
        // Add the WAYF/RM parameters
        idp.testModule.addRequestParameter("target", TARGET);
        idp.testModule.addRequestParameter("shire",POST_HANDLER);
        idp.testModule.addRequestParameter("providerId", SP_ENTITY);
        
        // Add a userid, as if provided by Basic Authentication or a Filter
        idp.request.setRemoteUser(NETID);
        
        // Block Attribute Push
        ShibbolethV1SSOHandler.pushAttributeDefault=false;
        
        // Call the IdP 
        idp.testModule.doGet();
        
        String bin64assertion = (String) idp.request.getAttribute("assertion");
        String assertion = new String(Base64.decodeBase64(bin64assertion.getBytes()));
        String handlerURL = (String) idp.request.getAttribute("shire");
        String targetURL = (String) idp.request.getAttribute("target");

        // Simulate the POST to the Filter Context using MockRunner
        filter.resetRequest("Shibboleth.sso/SAML/POST");
        filter.testModule.addRequestParameter("SAMLResponse",bin64assertion);
        filter.testModule.addRequestParameter("TARGET",targetURL);
        filter.request.setMethod("POST");
        filter.testModule.doFilter();
        
        // Now check up on what the Filter did with the POST
        MockHttpServletResponse response = filter.response;
        assertTrue(response.wasRedirectSent());
        Iterator cookies = response.getCookies().iterator();
        String cookiename = AuthenticationFilter.getCookieName(APPLICATIONID);
        String sessionId = null;
        while (cookies.hasNext()) {
            Cookie cookie = (Cookie) cookies.next();
            if (cookie.getName().equals(cookiename)) {
                sessionId = cookie.getValue();
                filter.request.addCookie(cookie);
                break;
            }
        }
        assertNotNull(sessionId);


        correctMockrunnerFilterRedirectBug();
        
        
        // Now get what was created in case you want to test it.
        Session session = context.getSessionManager().findSession(sessionId, APPLICATIONID);
        checkSession(session);
        
        filter.resetRequest("test.txt"); // need any URL
        filter.request.setMethod("GET");
        filter.testModule.doFilter();
        
        checkFilter();
        
    }
    
    /**
     * Test Filter Redirect with precreated Session, Post to Filter
     */
    public void testPrecreatedSessionFilterPost() 
        throws SAMLException, UnsupportedEncodingException {
        
        // Simulate the Resource Get 
        filter.resetRequest("test.txt");
        filter.request.setMethod("GET");
        filter.testModule.doFilter();
        
        // Now check up on what the Filter did
        MockHttpServletResponse response = filter.response;
        assertTrue(response.wasRedirectSent());
        Iterator cookies = response.getCookies().iterator();
        String cookiename = AuthenticationFilter.getCookieName(APPLICATIONID);
        String sessionId = null;
        Cookie sessionCookie = null;
        while (cookies.hasNext()) {
            Cookie cookie = (Cookie) cookies.next();
            if (cookie.getName().equals(cookiename)) {
                sessionId = cookie.getValue();
                sessionCookie=cookie;
                break;
            }
        }
        assertNotNull(sessionId);
        String redirectURL = response.getHeader("Location");
        assertTrue(redirectURL.indexOf(
                "target="+URLEncoder.encode(sessionId,"UTF-8"))>0);
        
        correctMockrunnerFilterRedirectBug();
        
        
        // Set the URL suffix that triggers SSO processing
        idp.resetRequest("SSO");
        
        // Add the WAYF/RM parameters
        idp.testModule.addRequestParameter("target", sessionId);
        idp.testModule.addRequestParameter("shire",POST_HANDLER);
        idp.testModule.addRequestParameter("providerId", SP_ENTITY);
        
        // Add a userid, as if provided by Basic Authentication or a Filter
        idp.request.setRemoteUser(NETID);
        
        // Block Attribute Push
        ShibbolethV1SSOHandler.pushAttributeDefault=false;
        
        // Call the IdP 
        idp.testModule.doGet();
        
        String bin64assertion = (String) idp.request.getAttribute("assertion");
        String assertion = new String(Base64.decodeBase64(bin64assertion.getBytes()));
        String handlerURL = (String) idp.request.getAttribute("shire");
        String targetURL = (String) idp.request.getAttribute("target");

        // Simulate the POST to the Filter Context using MockRunner
        filter.resetRequest("Shibboleth.sso/SAML/POST");
        filter.testModule.addRequestParameter("SAMLResponse",bin64assertion);
        filter.testModule.addRequestParameter("TARGET",targetURL);
        filter.request.setMethod("POST");
        if (sessionCookie!=null)
            filter.request.addCookie(sessionCookie);
        filter.testModule.doFilter();
        
        // Now check up on what the Filter did with the POST
        response = filter.response;
        assertTrue(response.wasRedirectSent());
        redirectURL = response.getHeader("Location");

        correctMockrunnerFilterRedirectBug();
        
        
        // Now get what was created in case you want to test it.
        Session session = context.getSessionManager().findSession(sessionId, APPLICATIONID);
        checkSession(session);
        
        filter.resetRequest("test.txt"); // need any URL
        filter.request.setMethod("GET");
        if (sessionCookie!=null)
            filter.request.addCookie(sessionCookie);
        filter.testModule.doFilter();
        
        checkFilter();
        
    }
    
    
    
    /**
     * Test Filter Redirect with precreated Session, Post to SP
     */
    public void testPrecreatedSessionSPPost() 
        throws SAMLException, UnsupportedEncodingException {
        
        // Simulate the Resource Get 
        filter.resetRequest("test.txt");
        filter.request.setMethod("GET");
        filter.testModule.doFilter();
        
        // Now check up on what the Filter did
        MockHttpServletResponse response = filter.response;
        assertTrue(response.wasRedirectSent());
        Iterator cookies = response.getCookies().iterator();
        String cookiename = AuthenticationFilter.getCookieName(APPLICATIONID);
        String sessionId = null;
        Cookie sessionCookie = null;
        while (cookies.hasNext()) {
            Cookie cookie = (Cookie) cookies.next();
            if (cookie.getName().equals(cookiename)) {
                sessionId = cookie.getValue();
                sessionCookie=cookie;
                break;
            }
        }
        assertNotNull(sessionId);
        String redirectURL = response.getHeader("Location");
        assertTrue(redirectURL.indexOf(
                "target="+URLEncoder.encode(sessionId,"UTF-8"))>0);
        
        correctMockrunnerFilterRedirectBug();
        
        
        // Set the URL suffix that triggers SSO processing
        idp.resetRequest("SSO");
        
        // Add the WAYF/RM parameters
        idp.testModule.addRequestParameter("target", sessionId);
        idp.testModule.addRequestParameter("shire",POST_SHIRE);
        idp.testModule.addRequestParameter("providerId", SP_ENTITY);
        
        // Add a userid, as if provided by Basic Authentication or a Filter
        idp.request.setRemoteUser(NETID);
        
        // Block Attribute Push
        ShibbolethV1SSOHandler.pushAttributeDefault=false;
        
        // Call the IdP 
        idp.testModule.doGet();
        
        String bin64assertion = (String) idp.request.getAttribute("assertion");
        String assertion = new String(Base64.decodeBase64(bin64assertion.getBytes()));
        String handlerURL = (String) idp.request.getAttribute("shire");
        String targetURL = (String) idp.request.getAttribute("target");

        // Simulate the POST to the SP Context using MockRunner
        consumer.resetRequest("Shibboleth.sso/SAML/POST");
        consumer.testModule.addRequestParameter("SAMLResponse",bin64assertion);
        consumer.testModule.addRequestParameter("TARGET",sessionId);
        consumer.testModule.doPost();
        
        // Now check up on what the AssertionConsumerServlet did with the POST
        response = consumer.response;
        assertTrue(response.wasRedirectSent());
        redirectURL = response.getHeader("Location");

        
        // Now get what was created in case you want to test it.
        Session session = context.getSessionManager().findSession(sessionId, APPLICATIONID);
        checkSession(session);
        
        filter.resetRequest("test.txt"); // need any URL
        filter.request.setMethod("GET");
        if (sessionCookie!=null)
            filter.request.addCookie(sessionCookie);
        filter.testModule.doFilter();
        
        checkFilter();
        
    }
    
    private void correctMockrunnerFilterRedirectBug() {
        // Mockrunner 0.3.6 (and before) has a bug. 
        // When a Filter ends with
        // Redirect and does not run out the entire chain, a
        // static interator is left hanging. This call circumvents
        // the problem by finishing the empty chain. It does not
        // actually call the Shibboleth Filter. It does nothing
        // other than to reset the static iterator. The next 
        // doFilter then starts over
        filter.testModule.doFilter();
    }
    
}

