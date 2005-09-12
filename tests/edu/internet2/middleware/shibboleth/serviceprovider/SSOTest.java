package edu.internet2.middleware.shibboleth.serviceprovider;

import org.apache.commons.codec.binary.Base64;
import org.opensaml.SAMLException;

import edu.internet2.middleware.shibboleth.idp.provider.ShibbolethV1SSOHandler;
import edu.internet2.middleware.shibboleth.resource.FilterSupport.NewSessionData;

/**
 * Test the IdP SSO function and the attribute fetch
 * @author gilbert
 *
 */
public class SSOTest extends SPTestCase {
    
    // The Mockrunner control blocks and the initialized IdP Servlet
    IdpTestContext idp;


    // data returned from SSO
    private String bin64assertion;
    private String assertion;
    private String handlerURL;
    private String targetURL;
    
    protected void setUp() throws Exception {
        super.setUp();
        
        // Initialize OpenSAML
        MockHTTPBindingProvider.setDefaultBindingProvider();
        
        // Initialize the IdP with the default configuration file.
        idp=new IdpTestContext();
        MockHTTPBindingProvider.idp=idp;
        
        // Initialize an SP Context and Confg
        initServiceProvider(); 
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
        
        bin64assertion = (String) idp.request.getAttribute("assertion");
        assertion = new String(Base64.decodeBase64(bin64assertion.getBytes()));
        handlerURL = (String) idp.request.getAttribute("shire");
        targetURL = (String) idp.request.getAttribute("target");
        
        
        /*
         * We could create Mockrunner control blocks to present this data
         * to the AuthenticationConsumer Servlet, but this level of 
         * intergration testing is supposed to check the processing of the
         * SAML objects. All the real work is done in SessionManager, so 
         * we might just as well go to it directly.
         */
        
        NewSessionData data = new NewSessionData();
        data.applicationId="default";
        data.handlerURL=handlerURL;
        data.ipaddr=idp.request.getRemoteAddr();
        data.providerId="https://sp.example.org/shibboleth";
        data.SAMLResponse = bin64assertion;
        data.target=targetURL;
        String sessionId = AssertionConsumerServlet.createSessionFromData(data);
        
        /*
         * Within the prevous call, the SAML assertion was presented to OpenSAML
         * for processing and the Attributes were stored.
         */
        
        // Now get what was created in case you want to test it.
        Session session = context.getSessionManager().findSession(sessionId, "default");
        
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
        
        // Force Attribute Push
        //ShibbolethV1SSOHandler.pushAttributeDefault=true;
        
        // Call the IdP 
        idp.testModule.doGet();
        
        bin64assertion = (String) idp.request.getAttribute("assertion");
        assertion = new String(Base64.decodeBase64(bin64assertion.getBytes()));
        handlerURL = (String) idp.request.getAttribute("shire");
        targetURL = (String) idp.request.getAttribute("target");
        
        
        
        NewSessionData data = new NewSessionData();
        data.applicationId="default";
        data.handlerURL=handlerURL;
        data.ipaddr=idp.request.getRemoteAddr();
        data.providerId="https://sp.example.org/shibboleth";
        data.SAMLResponse = bin64assertion;
        data.target=targetURL;
        String sessionId = AssertionConsumerServlet.createSessionFromData(data);
        
        
        // Now get what was created in case you want to test it.
        Session session = context.getSessionManager().findSession(sessionId, "default");
        
    }

}
