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

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import junit.framework.TestCase;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Level;
import org.opensaml.SAMLException;

import com.mockrunner.mock.web.MockHttpServletResponse;

import edu.internet2.middleware.shibboleth.idp.provider.ShibbolethV1SSOHandler;
import edu.internet2.middleware.shibboleth.resource.FilterUtil;
import edu.internet2.middleware.shibboleth.resource.FilterSupport.NewSessionData;
import edu.internet2.middleware.shibboleth.runner.ShibbolethRunner;
import edu.internet2.middleware.shibboleth.serviceprovider.AssertionConsumerServlet;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderContext;
import edu.internet2.middleware.shibboleth.serviceprovider.Session;
import edu.internet2.middleware.shibboleth.serviceprovider.SessionManager;

/**
 * A JUnit test case that exercises the IdP, SP, and Filter
 * @author Howard Gilbert
 */
public class IntegrationTest extends TestCase {
    
    ShibbolethRunner runner;
    ShibbolethRunner.IdpTestContext idp;
    ShibbolethRunner.AuthenticationFilterContext filter;
    
    
    
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
        runner.initializeSP();
        
        // Initialize the Filter and create its separate
        // Mockrunner simulated context. 
        filter= runner.getFilter();
            // Note: If you are going to change the Filter init-param
            // values, do it here before calling setUp()
        filter.setUp();
        
        // Create the static collection of Attributes that are 
        // returned by the IdP for every principal.
        // This could be done in each test, just as long as it
        // is done before the SSO.
        Attributes attributes = runner.getAttributesCollection();
        attributes.put(new BasicAttribute("eduPersonAffiliation", "member"));
        attributes.put(new BasicAttribute("eduPersonScopedAffiliation", "member"));
        attributes.put(new BasicAttribute("title", "clown"));
        attributes.put(new BasicAttribute("givenName", "bozo"));
        attributes.put(new BasicAttribute("surname", "Clown"));
    }
    
    
    public void testAttributePush() throws SAMLException {
        
        // Set the URL suffix that triggers SSO processing
        idp.setRequestUrls("SSO");
        
        // Add the WAYF/RM parameters
        idp.testModule.addRequestParameter("target", "https://nonsense");
        idp.testModule.addRequestParameter("shire","https://sp.example.org/Shibboleth.sso/SAML/POST");
        idp.testModule.addRequestParameter("providerId", "https://sp.example.org/shibboleth");
        
        // Add a userid, as if provided by Basic Authentication or a Filter
        idp.request.setRemoteUser("BozoTClown");
        
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
        
        
        // Build the parameter for Session creation
        NewSessionData data = new NewSessionData();
        FilterUtil.sessionDataFromRequest(data,idp.request);
            // there was no real redirect, so the next two fields are not
            // in the places that sessionDataFromRequest expects.
            data.SAMLResponse = bin64assertion;  
            data.target=targetURL;
        data.applicationId="default";
        data.handlerURL=handlerURL;
        data.providerId="https://sp.example.org/shibboleth";
        
        // Create the session, extract pushed Attributes 
        String sessionId = AssertionConsumerServlet.createSessionFromData(data);
        
        // Now get what was created in case you want to test it.
        ServiceProviderContext context   = ServiceProviderContext.getInstance();
        Session session = context.getSessionManager().findSession(sessionId, "default");
        
        // Pass the SessionId to the Filter, let it fetch the attributes
        filter.testModule.addRequestParameter("ShibbolethSessionId", sessionId);
        filter.setRequestUrls("test.txt");
        filter.testModule.doFilter();
        
            /*
             * Sanity Check: doFilter runs just the Filter itself. On 
             * input there was a Request and Response. When done, there
             * will be a replacement Request object created by the Filter
             * wrapping the original request and adding features.
             */
        
        // Get the Request Wrapper object created by the Filter
        HttpServletRequest filteredRequest = 
            (HttpServletRequest) filter.testModule.getFilteredRequest();
        
        // Now do something that uses Filter supplied logic
        Enumeration headerNames = filteredRequest.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String name = (String) headerNames.nextElement();
            String value = (String) filteredRequest.getHeader(name);
            System.out.println(name+ "-"+value );
        }
        
        
    }
    
    public void testAttributeQuery() throws SAMLException {
        
        // Set the URL suffix that triggers SSO processing
        idp.setRequestUrls("SSO");
        
        // Add the WAYF/RM parameters
        idp.testModule.addRequestParameter("target", "https://nonsense");
        idp.testModule.addRequestParameter("shire","https://sp.example.org/Shibboleth.sso/SAML/POST");
        idp.testModule.addRequestParameter("providerId", "https://sp.example.org/shibboleth");
        
        // Add a userid, as if provided by Basic Authentication or a Filter
        idp.request.setRemoteUser("BozoTClown");
        
        // Block Attribute Push
        ShibbolethV1SSOHandler.pushAttributeDefault=false;
        
        // Call the IdP 
        idp.testModule.doGet();
        
        String bin64assertion = (String) idp.request.getAttribute("assertion");
        String assertion = new String(Base64.decodeBase64(bin64assertion.getBytes()));
        String handlerURL = (String) idp.request.getAttribute("shire");
        String targetURL = (String) idp.request.getAttribute("target");
        
        
        // Build the parameter for Session creation
        NewSessionData data = new NewSessionData();
        FilterUtil.sessionDataFromRequest(data,idp.request);
        data.SAMLResponse = bin64assertion; // test logic 
        data.target=targetURL;
        data.applicationId="default";
        data.handlerURL=handlerURL;
        data.providerId="https://sp.example.org/shibboleth";
        
        // Create the Session
        // Internally an AA Query will fetch the attributes through the 
        // MockHTTPBindingProvider
        String sessionId = AssertionConsumerServlet.createSessionFromData(data);
        
        
        // Now get what was created in case you want to test it.
        ServiceProviderContext context   = ServiceProviderContext.getInstance();
        Session session = context.getSessionManager().findSession(sessionId, "default");
        StringBuffer buffer = SessionManager.dumpAttributes(session);
        System.out.println(buffer.toString());
        
        // Pass the SessionId to the Filter, let it fetch the attributes
        filter.testModule.addRequestParameter("ShibbolethSessionId", sessionId);
        filter.setRequestUrls("test.txt"); // need any URL
        filter.testModule.doFilter();
        
        // Get the Request Wrapper object created by the Filter
        HttpServletRequest filteredRequest = (HttpServletRequest) filter.testModule.getFilteredRequest();
        
        // Now do something that uses Filter supplied logic
        Enumeration headerNames = filteredRequest.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String name = (String) headerNames.nextElement();
            String value = (String) filteredRequest.getHeader(name);
            System.out.println(name+ "-"+value );
        }
    }
    
    public void testArtifact() throws SAMLException, UnsupportedEncodingException {
        
        // Set the URL suffix that triggers SSO processing
        idp.setRequestUrls("SSO");
        
        // Add the WAYF/RM parameters
        idp.testModule.addRequestParameter("target", "https://nonsense");
        idp.testModule.addRequestParameter("shire","https://sp.example.org/Shibboleth.sso/SAML/Artifact");
        idp.testModule.addRequestParameter("providerId", "https://sp.example.org/shibboleth");
        
        // Add a userid, as if provided by Basic Authentication or a Filter
        idp.request.setRemoteUser("BozoTClown");
        
        // Attribute Push is implied by Artifact
        ShibbolethV1SSOHandler.pushAttributeDefault=false;
        
        // Call the IdP 
        idp.testModule.doGet();
        
        MockHttpServletResponse response = idp.response;
        String redirectURL = response.getHeader("Location");
        
        String[] splits = redirectURL.split("\\&SAMLart=");
        assertTrue(splits.length>0);
        String[] samlArt = new String[splits.length-1];
        for (int i=0;i<samlArt.length;i++) {
            samlArt[i]=URLDecoder.decode(splits[i+1],"UTF-8");
        }
        
        
        
        // Build the parameter for Session creation
        NewSessionData data = new NewSessionData();
        FilterUtil.sessionDataFromRequest(data,idp.request);
        data.SAMLArt=samlArt;
        data.target="https://nonsense";
        data.applicationId="default";
        data.handlerURL="https://sp.example.org/Shibboleth.sso/SAML/Artifact";
        data.providerId="https://sp.example.org/shibboleth";
        
        // Create the Session
        // Internally an AA Query will fetch the attributes through the 
        // MockHTTPBindingProvider
        String sessionId = AssertionConsumerServlet.createSessionFromData(data);
        
        
        // Now get what was created in case you want to test it.
        ServiceProviderContext context   = ServiceProviderContext.getInstance();
        Session session = context.getSessionManager().findSession(sessionId, "default");
        StringBuffer buffer = SessionManager.dumpAttributes(session);
        System.out.println(buffer.toString());
        
        // Pass the SessionId to the Filter, let it fetch the attributes
        filter.testModule.addRequestParameter("ShibbolethSessionId", sessionId);
        filter.setRequestUrls("test.txt"); // need any URL
        filter.testModule.doFilter();
        
        // Get the Request Wrapper object created by the Filter
        HttpServletRequest filteredRequest = (HttpServletRequest) filter.testModule.getFilteredRequest();
        
        // Now do something that uses Filter supplied logic
        Enumeration headerNames = filteredRequest.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String name = (String) headerNames.nextElement();
            String value = (String) filteredRequest.getHeader(name);
            System.out.println(name+ "-"+value );
        }
    }
    
}
