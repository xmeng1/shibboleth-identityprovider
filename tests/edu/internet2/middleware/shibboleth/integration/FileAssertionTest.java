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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import junit.framework.TestCase;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Level;
import org.opensaml.SAMLException;
import org.opensaml.SAMLResponse;

import edu.internet2.middleware.shibboleth.idp.provider.ShibbolethV1SSOHandler;
import edu.internet2.middleware.shibboleth.resource.AuthenticationFilter;
import edu.internet2.middleware.shibboleth.resource.FilterUtil;
import edu.internet2.middleware.shibboleth.resource.FilterSupport.NewSessionData;
import edu.internet2.middleware.shibboleth.runner.MadSignertest;
import edu.internet2.middleware.shibboleth.runner.ShibbolethRunner;
import edu.internet2.middleware.shibboleth.runner.MadSignertest.MockIdp;
import edu.internet2.middleware.shibboleth.runner.ShibbolethRunner.IdpTestContext;
import edu.internet2.middleware.shibboleth.serviceprovider.AssertionConsumerServlet;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderConfig;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderContext;
import edu.internet2.middleware.shibboleth.serviceprovider.Session;

/**
 * JUnit tests that do not use an instance of the IdP.
 * Files containing assertions are read from /data and are
 * processed directly to the SP or else fed back from a 
 * file driven MockIdp. Tests of this form can be used
 * to generate non-standard input that the real IdP would
 * not generate.
 * 
 * @author Howard Gilbert
 */
public class FileAssertionTest extends TestCase {
    
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
    ShibbolethRunner.SPTestContext consumer;
    ShibbolethRunner.AuthenticationFilterContext filter;
    private NewSessionData newSessionData = new NewSessionData();
    ServiceProviderContext context;
    ServiceProviderConfig config;
    
    /*********** Services to replace the IdP ****************************/
    MadSignertest signer;
    MockIdp mockIdp;
    IdpTestContext idp;
    
    
    /**
     * TestCase setUp
     * 
     * <p>There is no IdP instance or configuration file.
     * A MockSignertest object will modify static assertion files,
     * and a MockIdP can be used to respond to SSO or other requests.</p>
     */
    protected void setUp() throws Exception {
        super.setUp();

        // Static call to set Log4J appenders and levels
        ShibbolethRunner.loglevel = Level.DEBUG;
        ShibbolethRunner.setupLogging();
        
        // Create the overall testing framework
        runner = new ShibbolethRunner();
        
        /************** MockIdp Setup ***********************************/
        
        // Setup a signer with the Example.org keystore
        signer = new MadSignertest("src/conf/idp-example.jks","exampleorg");
        
        // Now create a MockIdp from it
        mockIdp = signer.new MockIdp();
        
        // Create an IdpTestContext using this MockIdp
        idp = runner.new IdpTestContext(mockIdp);
        
        // Make sure it can be found by the MockHttpBindingProvider
        ShibbolethRunner.idp = idp;
        
        /************** end MockIdp setup *******************************/
        
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
        
    }
    
    /**
     * Test the Post Profile, Attribute Push from an XML Assertion file.
     * 
     * <p>This test does not use the real IdP or the MockIdp. 
     * It reads the assertion in directly from a file, and uses
     * the MadSignertest class directly to change its XML Id fields,
     * and timestamps and then resign it.
     * Call AssertionConsumerServlet directly, then Run Filter</p>
     */
    public void testFileAttributePush() throws Exception {
        
        
        /**************** Replace IdP with File *************************/
        // Read in and resign a test SAML Response file.
        SAMLResponse samlresponse = 
            signer.signResponseFile("data/AttributePushAssertion.xml", 
                    "tomcat");
        
        // Now feed the SAMLResponse into the AssertionConsumer
        String bin64assertion = new String(samlresponse.toBase64());
        newSessionData.SAMLResponse = bin64assertion; 
        /**************** end of IdP replacement ************************/
        
        newSessionData.target=TARGET;
        newSessionData.handlerURL=POST_SHIRE;
        
        // Create the session, extract pushed Attributes 
        String sessionId = AssertionConsumerServlet.createSessionFromData(newSessionData);
        
        // Now get what was created in case you want to test it.
        Session session = context.getSessionManager().findSession(sessionId, APPLICATIONID);
        checkSession(session);
        
        // Pass the SessionId to the Filter, let it fetch the attributes
        filter.resetRequest("test.txt");
        filter.testModule.addRequestParameter(AuthenticationFilter.SESSIONPARM, sessionId);
        filter.request.setMethod("GET");
        filter.testModule.doFilter();
        
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
     * Test Attribute Push using a Mock Idp.
     * 
     * <p>The MockIdp responds to Mockrunner calls for SSO, AA, or
     * Artifact, but you have to provide a path to a file with a
     * response you want sent back.
     */
    public void testMockIdp() throws SAMLException, KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
        
        /*********** Use MockIdp instead of real IdP ********************/
        // Tell the MockIdP how to respond to an SSO
        mockIdp.ssoResponseFile = "data/AttributePushAssertion.xml";
        // In attribute push, there will not be an AA query.
        /*********** That's it!, the rest is standard code **************/
        
        
        // Set the URL suffix that triggers SSO processing
        idp.resetRequest("SSO");
        
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
        filter.resetRequest("test.txt");
        filter.testModule.addRequestParameter(AuthenticationFilter.SESSIONPARM, sessionId);
        filter.request.setMethod("GET");
        filter.testModule.doFilter();
        
        checkFilter();
    }
    
    
}
