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
import java.net.URLDecoder;
import java.util.Enumeration;
import java.util.Map;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.servlet.http.HttpServletRequest;

import junit.framework.TestCase;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Level;
import org.opensaml.SAMLException;

import com.mockrunner.mock.web.MockHttpServletResponse;

import edu.internet2.middleware.shibboleth.idp.provider.ShibbolethV1SSOHandler;
import edu.internet2.middleware.shibboleth.resource.AuthenticationFilter;
import edu.internet2.middleware.shibboleth.resource.FilterUtil;
import edu.internet2.middleware.shibboleth.resource.FilterSupport.NewSessionData;
import edu.internet2.middleware.shibboleth.runner.ShibbolethRunner;
import edu.internet2.middleware.shibboleth.serviceprovider.AssertionConsumerServlet;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderConfig;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderContext;
import edu.internet2.middleware.shibboleth.serviceprovider.Session;

/**
 * A JUnit test case that exercises the IdP, SP, and Filter
 * @author Howard Gilbert
 */
public class IntegrationTest extends TestCase {
    
    // Create some constants, both as parameters and to test responses
    private static final String GIVENNAME = "Bozo";
    public static final String SURNAME = "Clown";
    private static final String TITLE = "clown";
    public static final String AFFILIATION = "member";
    public static final String SP_ENTITY = "https://sp.example.org/shibboleth";
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
        runner.setIdpConfigFileName("/basicIdpHome/idpconfig.xml"); // default value
        idp = runner.getIdp();
        
        // Initialize the SP with the default config file.
        runner.setSpConfigFileName("/basicSpHome/spconfig.xml"); // default value
        
        // Use one of two forms to initialize the SP
        // If only calling AssertionConsumerServlet.createSessionFromData directly
            //runner.initializeSP(); 
        // If calling AssertionConsumerServlet through MockRunner
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
     * Test the Post Profile, Attribute Push
     * <p>Run SSO, call AssertionConsumerServlet directly, then Run Filter</p>
     */
    public void testAttributePush() throws SAMLException {
        
        // Set the URL suffix that triggers SSO processing
        idp.setRequestUrls("SSO");
        
        // Add the WAYF/RM parameters
        idp.testModule.addRequestParameter("target", TARGET);
        idp.testModule.addRequestParameter("shire",POST_SHIRE);
        idp.testModule.addRequestParameter("providerId", SP_ENTITY);
        
        // Add a userid, as if provided by Basic Authentication or a Filter
        idp.request.setRemoteUser(NETID);
        
        // Force Attribute Push
        ShibbolethV1SSOHandler.pushAttributeDefault=true;
        
        // Call the IdP 
        idp.testModule.doGet();
        
            /*
             * Sanity check: The IdP normally ends by transferring control to a
             * JSP page that generates the FORM. However, we have not set up
             * Mockrunner to perform the transfer, because the form would just
             * create parsing work. Rather, the following code extracts the
             * information from the request attributes that the JSP would have
             * used as its source.
             */
        String bin64assertion = (String) idp.request.getAttribute("assertion");
        String assertion = new String(Base64.decodeBase64(bin64assertion.getBytes()));
        String handlerURL = (String) idp.request.getAttribute("shire");
        String targetURL = (String) idp.request.getAttribute("target");
        
        // Create the session directly without MockRunner
        FilterUtil.sessionDataFromRequest(newSessionData,idp.request);
            // there was no real redirect, so the next two fields are not
            // in the places that sessionDataFromRequest expects.
            newSessionData.SAMLResponse = bin64assertion;  
            newSessionData.target=targetURL;
        newSessionData.handlerURL=handlerURL;
        
        // Create the session, extract pushed Attributes 
        String sessionId = AssertionConsumerServlet.createSessionFromData(newSessionData);
        
        // Now get what was created in case you want to test it.
        Session session = context.getSessionManager().findSession(sessionId, APPLICATIONID);
        checkSession(session);
        
        // Pass the SessionId to the Filter, let it fetch the attributes
        filter.testModule.addRequestParameter(AuthenticationFilter.SESSIONPARM, sessionId);
        filter.setRequestUrls("test.txt");
        filter.testModule.doFilter();
        
            /*
             * Sanity Check: doFilter runs just the Filter itself. On 
             * input there was a Request and Response. When done, there
             * will be a replacement Request object created by the Filter
             * wrapping the original request and adding features.
             */

        checkFilter();
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
        
        
        Enumeration headerNames = filteredRequest.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String name = (String) headerNames.nextElement();
            String value = (String) filteredRequest.getHeader(name);
            System.out.println(name+ "-"+value );
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
        idp.setRequestUrls("SSO");
        
        // Add the WAYF/RM parameters
        idp.testModule.addRequestParameter("target", TARGET);
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
        consumer.testModule.addRequestParameter("SAMLResponse",bin64assertion);
        consumer.testModule.addRequestParameter("TARGET",targetURL);
        consumer.setRequestUrls("Shibboleth.sso/SAML/POST");
        consumer.testModule.doPost();
        
        // Now check up on what the AssertionConsumerServlet did with the POST
        MockHttpServletResponse response = consumer.response;
        assertTrue(response.wasRedirectSent());
        String redirectURL = response.getHeader("Location");
        
        // The SessionId is on the end of the redirected URL
        int pos = redirectURL.indexOf(AssertionConsumerServlet.SESSIONPARM);
        assertTrue(pos>0);
        String sessionId = redirectURL.substring(
                pos+AssertionConsumerServlet.SESSIONPARM.length()+1);
        
        // Now get what was created in case you want to test it.
        Session session = context.getSessionManager().findSession(sessionId, APPLICATIONID);
        checkSession(session);
        
        // Pass the SessionId to the Filter, let it fetch the attributes
        filter.testModule.addRequestParameter(AuthenticationFilter.SESSIONPARM, sessionId);
        filter.setRequestUrls("test.txt"); // need any URL
        filter.testModule.doFilter();
        
        checkFilter();
        
    }
    
    /**
     * Test Artifact
     * <p>Run SSO, call AssertionConsumerServlet directly, then Run Filter</p>
     */
    public void testArtifact() throws SAMLException, UnsupportedEncodingException {
        
        // Set the URL suffix that triggers SSO processing
        idp.setRequestUrls("SSO");
        
        // Add the WAYF/RM parameters
        idp.testModule.addRequestParameter("target", TARGET);
        idp.testModule.addRequestParameter("shire",ARTIFACT_SHIRE);
        idp.testModule.addRequestParameter("providerId", SP_ENTITY);
        
        // Add a userid, as if provided by Basic Authentication or a Filter
        idp.request.setRemoteUser(NETID);
        
        // Attribute Push is implied by Artifact
        ShibbolethV1SSOHandler.pushAttributeDefault=false;
        
        // Call the IdP 
        idp.testModule.doGet();
        
        // Now check the response from the IdP
        MockHttpServletResponse response = idp.response;
        assertTrue(response.wasRedirectSent());
        String redirectURL = response.getHeader("Location");
        
        // The artifacts were appended to the end of the Redirect URL
        String[] splits = redirectURL.split("\\&SAMLart=");
        assertTrue(splits.length>1);
        String[] artifactArray = new String[splits.length-1];
        for (int i=0;i<artifactArray.length;i++) {
            artifactArray[i]=URLDecoder.decode(splits[i+1],"UTF-8");
        }
        
        // Build the parameter for Session creation
        FilterUtil.sessionDataFromRequest(newSessionData,idp.request);
        newSessionData.SAMLArt=artifactArray;
        newSessionData.target=TARGET;
        newSessionData.handlerURL=ARTIFACT_SHIRE;
        
        // Create the Session
        // Under the covers, SAML will see the Artifact and fetch the Assertion
        String sessionId = AssertionConsumerServlet.createSessionFromData(newSessionData);
        
        
        // Now get what was created in case you want to test it.
        Session session = context.getSessionManager().findSession(sessionId, APPLICATIONID);
        checkSession(session);
        
        
        // Pass the SessionId to the Filter, let it fetch the attributes
        filter.testModule.addRequestParameter(AuthenticationFilter.SESSIONPARM, sessionId);
        filter.setRequestUrls("test.txt"); // need any URL
        filter.testModule.doFilter();

        checkFilter();
     }
    
}
