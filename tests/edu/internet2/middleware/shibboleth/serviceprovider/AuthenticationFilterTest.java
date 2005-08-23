package edu.internet2.middleware.shibboleth.serviceprovider;
import java.io.File;

import com.mockrunner.mock.web.MockFilterConfig;
import com.mockrunner.mock.web.MockHttpServletRequest;
import com.mockrunner.mock.web.MockHttpServletResponse;
import com.mockrunner.mock.web.MockServletContext;
import com.mockrunner.mock.web.WebMockObjectFactory;
import com.mockrunner.servlet.ServletTestModule;

import edu.internet2.middleware.shibboleth.resource.AuthenticationFilter;
import edu.internet2.middleware.shibboleth.resource.FilterSupport;
import edu.internet2.middleware.shibboleth.resource.FilterSupport.RMAppInfo;

/**
 * Use Mockrunner to test the Shib Filter
 */
public class AuthenticationFilterTest extends SPTestCase {
	
	// The Factory creates the Request, Response, Session, etc.
	WebMockObjectFactory factory = new WebMockObjectFactory();
    
    // The TestModule runs the Servlet and Filter methods in the simulated container
	ServletTestModule testModule = new ServletTestModule(factory);
    
    // Now simulated Servlet API objects
	MockServletContext servletContext= new MockServletContext();
	MockFilterConfig filterConfig= factory.getMockFilterConfig();
    MockHttpServletResponse response = factory.getMockResponse();
    MockHttpServletRequest request = factory.getMockRequest();
	
	// Filter objects
	private AuthenticationFilter filter;
	
	// SP configuration objects
	private FilterSupport service;
	private RMAppInfo rmAppInfo;

	protected void setUp() throws Exception {
		super.setUp();
		
        // ServletContext (argument to Filters and Servlets)
		servletContext.setServletContextName("dummy Servlet Context");
        servletContext.setInitParameter("requireId", ".+/test.+");
		
		// The FilterConfig (argument to Filter init)
		filterConfig.setupServletContext(servletContext);
		filterConfig.setFilterName("Test Filter under JUnit");
		
		// Create instance of Filter class, add to chain, call its init()
		filter = (AuthenticationFilter) testModule.createFilter(AuthenticationFilter.class);
        
		// Initialize an SP Context and Confg
		String configFileName = new File("data/spconfig.xml").toURI().toString();
		initServiceProvider(configFileName); 
		
		// Plug an instance of FilterSupportImpl into the Filter
		service = new FilterSupportImpl();
		AuthenticationFilter.setFilterSupport(service);

        // Get our own copy of SP Config info for Assert statements
		rmAppInfo = service.getRMAppInfo("default");

        request.setRemoteAddr("127.0.0.1");
        request.setContextPath("/secure");
        request.setProtocol("HTTP/1.1");
        request.setScheme("https");
        request.setServerName("sp.example.org");
        request.setServerPort(9443);
	}
    
    void setRequestUrls(String suffix) {
        request.setMethod("GET");
        request.setRequestURI("http://sp.example.org:9443/secure/"+suffix);
        request.setRequestURL("http://sp.example.org:9443/secure/"+suffix);
        request.setServletPath("/secure/"+suffix);
        
    }
	
	public void testInitialGET() {
		
		setRequestUrls("test.txt");
        
		// Run the Filter against the request
		testModule.doFilter();
		
		// It should generate a Redirect to the WAYF, with added parameters
		assertTrue(response.wasRedirectSent());
		String wayfurl = response.getHeader("Location");
		assertEquals(rmAppInfo.wayfUrl,wayfurl.substring(0,wayfurl.indexOf('?')));
	}

}
