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

import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.servlet.http.HttpServletRequest;

import junit.framework.TestCase;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Level;
import org.opensaml.SAMLResponse;

import edu.internet2.middleware.shibboleth.resource.AuthenticationFilter;
import edu.internet2.middleware.shibboleth.resource.FilterSupport.NewSessionData;
import edu.internet2.middleware.shibboleth.runner.MadSignertest;
import edu.internet2.middleware.shibboleth.runner.ShibbolethRunner;
import edu.internet2.middleware.shibboleth.serviceprovider.AssertionConsumerServlet;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderConfig;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderContext;
import edu.internet2.middleware.shibboleth.serviceprovider.Session;

/**
 * A JUnit test case that exercises the IdP, SP, and Filter
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
     * Test the Post Profile, Attribute Push
     * <p>Run SSO, call AssertionConsumerServlet directly, then Run Filter</p>
     */
    public void testAttributePush() throws Exception {
        
        MadSignertest signer = new MadSignertest("src/conf/idp-example.jks","exampleorg");
        SAMLResponse samlresponse = 
            signer.signResponseFile("data/AttributePushAssertion.xml", 
                    "tomcat", new Date());
        
        
        String bin64assertion = new String(samlresponse.toBase64());
        String assertion = new String(Base64.decodeBase64(bin64assertion.getBytes()));
        
        newSessionData.SAMLResponse = bin64assertion; 
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
    
}
