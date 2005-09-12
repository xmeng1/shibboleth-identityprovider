package edu.internet2.middleware.shibboleth.serviceprovider;

import com.mockrunner.mock.web.MockFilterConfig;
import com.mockrunner.mock.web.MockHttpServletRequest;
import com.mockrunner.mock.web.MockHttpServletResponse;
import com.mockrunner.mock.web.MockServletContext;
import com.mockrunner.mock.web.WebMockObjectFactory;
import com.mockrunner.servlet.ServletTestModule;

import edu.internet2.middleware.shibboleth.idp.IdPResponder;

/**
 * Establish initialized IdP to respond to requests.
 * 
 * <p>The IdP is initialized when the IdpResponder servlet init() is 
 * called. This establishes the static context of tables that 
 * allow the IdP to issue a Subject and then respond when that
 * Subject is returned in an Attribute Query.</p>
 * 
 * <p>This class creates the Mockrunner control blocks needed to 
 * call the IdP and, by creating the IdP Servlet object, also 
 * initializes an instance of the IdP. It depends on a configuration
 * file located as a resource in the classpath, typically in the 
 * /testresources directory of the project.</p>
 */
public class IdpTestContext {
    
    // Default to a configuration in /testresources
    public static String defaultConfigFileName = "/basicIdpHome/idpconfig.xml";
    
    // The Factory creates the Request, Response, Session, etc.
    public WebMockObjectFactory factory = new WebMockObjectFactory();
    
    // The TestModule runs the Servlet and Filter methods in the simulated container
    public ServletTestModule testModule = new ServletTestModule(factory);
    
    // Now simulated Servlet API objects
    MockServletContext servletContext= factory.getMockServletContext();
    MockFilterConfig filterConfig= factory.getMockFilterConfig();
    MockHttpServletResponse response = factory.getMockResponse();
    MockHttpServletRequest request = factory.getMockRequest();
    
    
    // The IdP Servlet that processes SSO, AA, and Artifact requests
    // The object is created by Mockrunner
    public IdPResponder idpServlet;
    
    /**
     * Construct with the default configuration file
     */
    public IdpTestContext() {
        this(defaultConfigFileName);
    }
    
    /**
     * Construct using a specified IdP configuration file.
     */
    public IdpTestContext(String configFileName) {
        
        // ServletContext
        servletContext.setServletContextName("dummy IdP Context");
        servletContext.setInitParameter("IdPConfigFile", configFileName);
        
        
        // Create instance of Filter class, add to chain, call its init()
        idpServlet = (IdPResponder) testModule.createServlet(IdPResponder.class);
        
        // Initialize the unchanging properties of the HttpServletRequest
        request.setRemoteAddr("127.0.0.1");
        request.setContextPath("/shibboleth-idp");
        request.setProtocol("HTTP/1.1");
        request.setScheme("https");
        request.setServerName("idp.example.org");
        request.setServerPort(443);
        
    }
    
    /**
     * Set all fields of the HttpServletRequest that relate to a particular
     * Servlet, extra path, and query.
     * @param suffix Everything after the context (no leading "/")
     */
    void setRequestUrls(String suffix) {
        request.setRequestURI("https://idp.example.org/shibboleth-idp/"+suffix);
        request.setRequestURL("https://idp.example.org/shibboleth-idp/"+suffix);
        request.setServletPath("/shibboleth.idp/"+suffix);
        
    }
    
}
