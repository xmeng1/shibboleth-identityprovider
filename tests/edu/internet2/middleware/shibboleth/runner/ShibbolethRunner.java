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

package edu.internet2.middleware.shibboleth.runner;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.servlet.http.HttpServlet;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Layout;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.opensaml.SAMLBinding;
import org.opensaml.SAMLConfig;

import com.mockrunner.mock.web.MockFilterConfig;
import com.mockrunner.mock.web.MockHttpServletRequest;
import com.mockrunner.mock.web.MockHttpServletResponse;
import com.mockrunner.mock.web.MockServletContext;
import com.mockrunner.mock.web.WebMockObjectFactory;
import com.mockrunner.servlet.ServletTestModule;

import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.idp.IdPResponder;
import edu.internet2.middleware.shibboleth.resource.AuthenticationFilter;
import edu.internet2.middleware.shibboleth.serviceprovider.AssertionConsumerServlet;
import edu.internet2.middleware.shibboleth.serviceprovider.FilterSupportImpl;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderConfig;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderContext;

/**
 * A JUnit Test support class for Shibboleth.
 * 
 * <p>This class can create the Mockrunner control blocks to 
 * interface to an instance of the SP and one or more instances
 * of the IdP and Resource Filter. Each instance is initialized
 * with its own set of configuration files. The test only needs
 * to create the objects it needs.</p>
 * 
 * <p>Look at *.integration.IntegrationTest for an example of use.</p>
 * 
 * @author Howard Gilbert.
 */
public class ShibbolethRunner {
    
    // Default values used to define each context
    public static String REMOTE_ADDR = "192.168.0.99";
    public static String SCHEME = "https";
    public static String PROTOCOL = "HTTP/1.1";
    public static int    SERVER_PORT = 443;
    
    // IdP
    public static String IDP_SERVER_NAME = "idp.example.org";
    public static String IDP_CONTEXT_PATH = "/shibboleth-idp";
    public static String IDP_CONTEXT_URL = SCHEME+"://"+IDP_SERVER_NAME+IDP_CONTEXT_PATH+"/";
    
    // SP
    public static String SP_SERVER_NAME = "sp.example.org";
    public static String SP_CONTEXT_PATH = "/shibboleth-sp";
    public static String SP_CONTEXT_URL = SCHEME+"://"+SP_SERVER_NAME+SP_CONTEXT_PATH+"/";
    
    // Resource
    public static int    RESOURCE_SERVER_PORT = 9443;
    public static String RESOURCE_CONTEXT_PATH = "/secure";
    public static String RESOURCE_CONTEXT_URL = SCHEME+"://"+SP_SERVER_NAME+":"+RESOURCE_SERVER_PORT+RESOURCE_CONTEXT_PATH+"/";
    
    
    public static SAMLConfig samlConfig; // See constructor for use

    
    
 
    /********************* Static Methods **********************/
    
    /*
     * Logging
     * 
     * For automated test cases that normally just work, you 
     * probably want to leave the logging level to ERROR. However,
     * if you are running a custom test case to discover the source
     * of a problem, or when building a new test case, then you 
     * may want to set the logging level to DEBUG.
     * 
     * You can change the loglevel variable from the test case
     * code before calling setupLogging(). 
     */
    public static Level loglevel = Level.INFO;
    
    private static Logger clientLogger = Logger.getLogger("edu.internet2.middleware.shibboleth");
    private static Logger initLogger = Logger.getLogger("shibboleth.init");
    private static Logger samlLogger = Logger.getLogger("org.opensaml");
    private static boolean manageLogs = false;
    
    /**
     * You will almost always call setupLogging first, but it
     * it not automatic in case you have exotic logging 
     * requirements.
     * 
     * <p>Restriction: avoid any static initialization that generates
     * log messages because this method can only be called after 
     * static initialation.</p>
     */
    public static void setupLogging() {
        manageLogs = true;
        Logger root = Logger.getRootLogger();
        Layout initLayout = new PatternLayout("%d{HH:mm} %-5p %m%n");
        ConsoleAppender consoleAppender= new ConsoleAppender(initLayout,ConsoleAppender.SYSTEM_OUT);
        root.removeAllAppenders();
        root.addAppender(consoleAppender);
        root.setLevel(Level.ERROR);
        clientLogger.removeAllAppenders();
        clientLogger.setLevel(loglevel);
        initLogger.removeAllAppenders();
        initLogger.setLevel(loglevel);
        samlLogger.removeAllAppenders();
        samlLogger.setLevel(loglevel);
    }
    
    /**
     * Sometimes (as in IdP initialization) the logging levels
     * get reset to some unintended level. This resets them
     * to whatever we want for testing.
     */
    public static void resetLoggingLevels() {
        if (!manageLogs) return;  // If setupLogging was never called.
        clientLogger.removeAllAppenders();
        clientLogger.setLevel(loglevel);
        initLogger.removeAllAppenders();
        initLogger.setLevel(loglevel);
        samlLogger.removeAllAppenders();
        samlLogger.setLevel(loglevel);
        
    }
    
    
    
    
    
    /********************* Constructors ************************
     * Initialization logic goes here.
     * <p>Reqires that Log4J already be configured.</p>
     */
    public ShibbolethRunner() {
        configureTestSAMLQueries();
    }

    /**
     * SAML has a list of BindingProviders that access the IdP.
     * Normally the SOAP HTTP BindingProvider is the default and
     * it accesses the IdP by creating a URL socket. This code 
     * replaces that default with a Mockrunner BindingProvider.
     * So when the SP does an AA or Artifact Query, the IdP is
     * called using its Mockrunner simulated Servlet context.
     * 
     * <p>Note: This method depends on a real IdP context created
     * using the IdPTestContext. Use another method if you want
     * to feed back pre-created test responses.</p>
     */
    private void configureTestSAMLQueries() {
        samlConfig = SAMLConfig.instance();
        samlConfig.setDefaultBindingProvider(SAMLBinding.SOAP,
                "edu.internet2.middleware.shibboleth.runner.MockHTTPBindingProvider" );
    }
    
    
    
    
    
    
    
    
    /************************* Service Provider ********************
     * The SP is represented by an SPContext object and the objects
     * SessionManager, SPConfig, etc. chained off it. The context
     * is initialized and then the main configuration file is read
     * in to create the Config object.
     */
    
    private String spConfigFileName = "/basicSpHome/spconfig.xml";
    /**
     * If you are goint to change the SP Config File
     * do it before calling initServiceProvider or constructing
     * an SPTestContext.
     * 
     * @param spConfigFileName
     */
    public void setSpConfigFileName(String spConfigFileName) {
        this.spConfigFileName = spConfigFileName;
    }
    
    private static boolean SPinitialized = false; // don't do it twice
    public static SPTestContext consumer = null;
    
    /**
     * Initialize an instance of the SP context and configuration.
     * 
     * @throws ShibbolethConfigurationException  if bad config file
     */
    public void initializeSP() 
        throws ShibbolethConfigurationException{
        if (SPinitialized) return;
        SPinitialized=true;
        
        ServiceProviderContext context = ServiceProviderContext.getInstance();
        context.initialize();
        
        ServiceProviderConfig config = new ServiceProviderConfig();
        context.setServiceProviderConfig(config);
        config.loadConfigObjects(spConfigFileName);
        
        // Plug an instance of FilterSupportImpl into the Filter
        FilterSupportImpl service = new FilterSupportImpl();
        AuthenticationFilter.setFilterSupport(service);
        
    }
    
    
    /**
     * A MockRunner interface object for the AssertionConsumerServlet.
     * 
     * <p>The SP itself is a static set of objects initialized 
     * under the ServiceProviderContext. There can be only one
     * SP per ClassLoader, so there is no way to test multiple 
     * SPs at the same time. However, SPs don't interact, so it
     * doesn't matter.</p>
     * 
     * <p>If more than one SPTestContext object is created, they
     * share the same SPContext objects.
     */
    public class SPTestContext {

        // The Factory creates the Request, Response, Session, etc.
        public WebMockObjectFactory factory = new WebMockObjectFactory();
        
        // The TestModule runs the Servlet and Filter methods in the simulated container
        public ServletTestModule testModule = new ServletTestModule(factory);
        
        // Now simulated Servlet API objects
        public MockServletContext servletContext= factory.getMockServletContext();
        public MockFilterConfig filterConfig= factory.getMockFilterConfig();
        public MockHttpServletResponse response = factory.getMockResponse();
        public MockHttpServletRequest request = factory.getMockRequest();
        
        public AssertionConsumerServlet spServlet;
        
        
        /**
         * Construct the related objects
         * @throws ShibbolethConfigurationException 
         */
        public SPTestContext() throws ShibbolethConfigurationException {
            
            // ServletContext
            servletContext.setServletContextName("dummy SP Context");
            servletContext.setInitParameter("ServiceProviderConfigFile", spConfigFileName);
            
            // Create the Servlet object, but do not run its init()
            // instead use the initializeSP() routine which does 
            // the same initialize in the test environment
            spServlet = new AssertionConsumerServlet();
            testModule.setServlet(spServlet, false);
            initializeSP();
            
        }
        
        /**
         * Set the fields of the request that depend on a suffix,
         */
        public void resetRequest(String suffix) {
            request.resetAll();
            response.resetAll();
            
            // Unchanging properties of the HttpServletRequest
            request.setRemoteAddr(REMOTE_ADDR);
            request.setContextPath(SP_CONTEXT_PATH);
            request.setProtocol(PROTOCOL);
            request.setScheme(SCHEME);
            request.setServerName(SP_SERVER_NAME);
            request.setServerPort(SERVER_PORT);
            
            request.setRequestURI(SP_CONTEXT_URL+suffix);
            request.setRequestURL(SP_CONTEXT_URL+suffix);
            request.setServletPath(SP_CONTEXT_PATH+"/"+suffix);
        }
        
    }

    
    
    
    
    
    /************************ IdP ******************************
     * Setup the IdP interface object
     * 
     * The IdP associates its "context" of cached data and configured 
     * objects with the IdPResponder Servlet object. They are 
     * initialized when the Servlet init() is called. It is 
     * possible to create more than one IdpTestContext object
     * representing different configuration files, or a new
     * IdpTestContext can be created with fresh Mockrunner object
     * on top of an existing initialized IdP.
     * 
     * To direct the AA and Artifact queries back to the Idp object,
     * a call to SAML sets up the MockHTTPBindingProvider to replace
     * the normal HTTPBindingProvider. Thus instead of creating URL
     * and sockets to talk to the IdP, a simulated Request object is
     * configured and the IdP is called through MockRunner.
     */
    public String idpConfigFileName = "/basicIdpHome/idpconfig.xml";
    public void setIdpConfigFileName(String idpConfigFileName) {
        this.idpConfigFileName = idpConfigFileName;
    } 
    
    /**
     * Although it is possible in theory to have more than one IdP 
     * running in a TestCase, this one static IdpTestContext
     * pointer tells the MockHTTPBindingProvider which IdP
     * to use for AA and Artifact queries. If you have more
     * that one IdP, the TestCase has to figure out how to swap this
     * pointer between them.  
     */
    public static IdpTestContext idp = null;
    
    /**
     * Initializes the IdP if necessary, then returns a 
     * pointer to the MockRunner interface object
     * 
     * @return IdpTestContext with Mockrunner objects
     */
    public IdpTestContext getIdp() {
        if (idp==null) {
            idp = new IdpTestContext();
        }
        return idp;
    }
    
    
    /**
     * A set of Mockrunner control blocks to call a newly initialized
     * or previously created IdP. 
     * 
     * <p>By default, an IdpTestContext creates a new instance of the
     * IdP using the current configuration file. However, if an 
     * already intialized IdPResponder servlet is passed to the
     * constructor, then new Mockrunner blocks are created but
     * the existing IdP is reused.</p>
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
        
        

        // The Factory creates the Request, Response, Session, etc.
        public WebMockObjectFactory factory = new WebMockObjectFactory();
        
        // The TestModule runs the Servlet and Filter methods in the simulated container
        public ServletTestModule testModule = new ServletTestModule(factory);
        
        // Now simulated Servlet API objects
        public MockServletContext servletContext= factory.getMockServletContext();
        public MockFilterConfig filterConfig= factory.getMockFilterConfig();
        public MockHttpServletResponse response = factory.getMockResponse();
        public MockHttpServletRequest request = factory.getMockRequest();
        
        
        // The IdP Servlet that processes SSO, AA, and Artifact requests
        public HttpServlet idpServlet;
        
        /**
         * Construct new context and new IdP from the configuration file.
         */
        public IdpTestContext() {
            this(null);
        }
        
        /**
         * Create a new Mockrunner context. If an previous
         * IdP was initialized in a prior context, reuse it 
         * and therefore only refresh the Mockrunner objects.
         * Otherwise, initialize a new instance of the IdP.
         */
        public IdpTestContext(HttpServlet oldidp) {
            
            // ServletContext
            servletContext.setServletContextName("dummy IdP Context");
            servletContext.setInitParameter("IdPConfigFile", idpConfigFileName);
            
            if (oldidp==null) {
                idpServlet = new IdPResponder();
                // NOTE: The IdP reads its configuration file and initializes
                // itself within this call.
                testModule.setServlet(idpServlet,true);
            resetLoggingLevels();
            } else {
                // reuse an existing initialized servlet
                idpServlet=oldidp;
                testModule.setServlet(idpServlet,false);
            }
        }
        
        
        /**
         * Set the fields of the request that depend on a suffix,
         * normally SSO, AA, or Artifact
         */
        public void resetRequest(String suffix) {
            
            request.resetAll();
            response.resetAll();
            
            // Unchanging properties of the HttpServletRequest
            request.setRemoteAddr(REMOTE_ADDR);
            request.setContextPath(IDP_CONTEXT_PATH);
            request.setProtocol(PROTOCOL);
            request.setScheme(SCHEME);
            request.setServerName(IDP_SERVER_NAME);
            request.setServerPort(SERVER_PORT);
            
            request.setRequestURI(IDP_CONTEXT_URL+suffix);
            request.setRequestURL(IDP_CONTEXT_URL+suffix);
            request.setServletPath(IDP_CONTEXT_PATH+"/"+suffix);
        }
        
    }

    
    
    
    
    /********************** Attribute Source ***********************
     * Here we keep a static reference to a Collection of Attributes. 
     * 
     * The Test can clear the collection and add attributes. When
     * the IdP needs attributes, it treats this collection as the 
     * starting point and processes them through ARP. When then get
     * to the SP they go through AAP. So you can test the Attribute
     * processing logic in both components by creating Attributes 
     * with names and values that are accepted or rejected.
     */
    
    public static BasicAttributes attributes = new BasicAttributes();
    
    /**
     * The Test should obtain a reference to the Attribute collection and add
     * such attributes as it wants the IdP to return for a Principal.
     * @return Attributes collection
     */
    public Attributes getAttributesCollection() {
        return attributes;
    }
    
    
    
    
    
    /*************************** Resource Manage Filter *****************
     * The Filter depends on a Servlet environment simulated by MockRunner.
     * We give it its own set of MockRunner blocks because in real life
     * it runs in a separate context from the SP or IdP.
     * 
     * The Filter depends on the SP and, once initialized, has a reference
     * to FilterSupportImpl and through it the SP configuration and Sessions.
     */
    private AuthenticationFilterContext filter;
    public AuthenticationFilterContext getFilter() throws ShibbolethConfigurationException {
        if (filter==null)
            filter=new AuthenticationFilterContext();
        return filter;
    }
    
    /**
     * Create the MockRunning interface for running the ServletFilter.
     * 
     * <p>The AuthenticationFilter object itself contains no 
     * meaningful state, so you can create multiple instances
     * of this interface object to represent more than one
     * Resource context being managed by the same SP.</p>
     *
     */
    public class AuthenticationFilterContext {
        

        // The Factory creates the Request, Response, Session, etc.
        public WebMockObjectFactory factory = new WebMockObjectFactory();
        
        // The TestModule runs the Servlet and Filter methods in the simulated container
        public ServletTestModule testModule = new ServletTestModule(factory);
        
        // Now simulated Servlet API objects
        public MockServletContext servletContext= factory.getMockServletContext();
        public MockFilterConfig filterConfig= factory.getMockFilterConfig();
        public MockHttpServletResponse response = factory.getMockResponse();
        public MockHttpServletRequest request = factory.getMockRequest();
        
        // Filter objects
        private AuthenticationFilter filter;
        
       public AuthenticationFilterContext() {
            
            // Dummy web.xml for Resouce context
            servletContext.setServletContextName("dummy Servlet Context");
            
            // Dummy <Filter> in dummy web.xml
            MockServletContext filterParameters = new MockServletContext();
            filterParameters.setInitParameter("requireId", ".+/test.+");
            filterConfig.setupServletContext(filterParameters);
            filterConfig.setFilterName("Test Filter under JUnit");
       }
       
       /**
        * Call after any changes to Context init-param values to
        * initialize the filter object and connect to the SP.
        * 
        * @throws ShibbolethConfigurationException from SP init.
        */
       public void setUp() throws ShibbolethConfigurationException {
            
            // Create instance of Filter class, add to chain, call its init()
            filter = new AuthenticationFilter();
            testModule.addFilter(filter,true);
            
            // Note: if the SP is already initialized, this noops.
            initializeSP();
            

        }
        
        public void resetRequest(String suffix) {
            
            request.setRemoteAddr(REMOTE_ADDR);
            request.setContextPath(RESOURCE_CONTEXT_PATH);
            request.setProtocol(PROTOCOL);
            request.setScheme(SCHEME);
            request.setServerName(SP_SERVER_NAME);
            request.setServerPort(RESOURCE_SERVER_PORT);

            request.setMethod("GET");
            request.setRequestURI(RESOURCE_CONTEXT_URL+suffix);
            request.setRequestURL(RESOURCE_CONTEXT_URL+suffix);
            request.setServletPath(RESOURCE_CONTEXT_PATH+"/"+suffix);
            
        }
    }
    
}
