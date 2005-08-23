package edu.internet2.middleware.shibboleth.serviceprovider;

import java.io.File;

import org.apache.commons.codec.binary.Base64;
import org.opensaml.SAMLException;

import com.mockrunner.mock.web.MockFilterConfig;
import com.mockrunner.mock.web.MockHttpServletRequest;
import com.mockrunner.mock.web.MockHttpServletResponse;
import com.mockrunner.mock.web.MockServletContext;
import com.mockrunner.mock.web.WebMockObjectFactory;
import com.mockrunner.servlet.ServletTestModule;

import edu.internet2.middleware.shibboleth.idp.IdPResponder;
import edu.internet2.middleware.shibboleth.idp.provider.ShibbolethV1SSOHandler;
import edu.internet2.middleware.shibboleth.resource.FilterSupport.NewSessionData;

public class SSOTest extends SPTestCase {

    // The Factory creates the Request, Response, Session, etc.
    WebMockObjectFactory factory = new WebMockObjectFactory();
    
    // The TestModule runs the Servlet and Filter methods in the simulated container
    ServletTestModule testModule = new ServletTestModule(factory);
    
    // Now simulated Servlet API objects
    MockServletContext servletContext= factory.getMockServletContext();
    MockFilterConfig filterConfig= factory.getMockFilterConfig();
    MockHttpServletResponse response = factory.getMockResponse();
    MockHttpServletRequest request = factory.getMockRequest();
    
    // Servlet objects
    private IdPResponder sso;

    // data returned from SSO
    private String bin64assertion;
    private String assertion;
    private String handlerURL;
    private String targetURL;
    
    protected void setUp() throws Exception {
        super.setUp();
        
        // ServletContext (argument to Filters and Servlets)
        servletContext.setServletContextName("dummy SSO Context");
        servletContext.setInitParameter("IdPConfigFile", "file:/C:/usr/local/shibboleth-idp/etc/idp.xml");
        
        
        // Create instance of Filter class, add to chain, call its init()
        sso = (IdPResponder) testModule.createServlet(IdPResponder.class);
        
        // Initialize an SP Context and Confg
        String configFileName = new File("data/spconfig.xml").toURI().toString();
        initServiceProvider(configFileName); 
        

        request.setRemoteAddr("127.0.0.1");
        request.setContextPath("/shibboleth-idp");
        request.setProtocol("HTTP/1.1");
        request.setScheme("https");
        request.setServerName("idp.example.org");
        request.setServerPort(443);
    }
    
    void setRequestUrls(String suffix) {
        request.setMethod("GET");
        request.setRequestURI("https://idp.example.org/shibboleth-idp/"+suffix);
        request.setRequestURL("https://idp.example.org/shibboleth-idp/"+suffix);
        request.setServletPath("/shibboleth.idp/"+suffix);
        
    }
    
    public void testInitialGET() throws SAMLException {
        
        setRequestUrls("SSO");
        testModule.addRequestParameter("target", "https://nonsense");
        testModule.addRequestParameter("shire","https://sp.example.org/Shibboleth.sso/SAML/POST");
        testModule.addRequestParameter("providerId", "https://sp.example.org/shibboleth");
        request.setRemoteUser("BozoTClown");
        
        ShibbolethV1SSOHandler.pushAttributeDefault=true;
        
        testModule.doGet();
        
        bin64assertion = (String) request.getAttribute("assertion");
        assertion = new String(Base64.decodeBase64(bin64assertion.getBytes()));
        handlerURL = (String) request.getAttribute("shire");
        targetURL = (String) request.getAttribute("target");
        
        // There is no need to use the Servlet interface to consume it
        NewSessionData data = new NewSessionData();
        data.applicationId="default";
        data.handlerURL=handlerURL;
        data.ipaddr=request.getRemoteAddr();
        data.providerId="https://sp.example.org/shibboleth";
        data.SAMLResponse = bin64assertion;
        data.target=targetURL;
        String sessionId = AssertionConsumerServlet.createSessionFromData(data);
        
        // Now get what was created in case you want to test it.
        Session session = context.getSessionManager().findSession(sessionId, "default");
        
    }


}
