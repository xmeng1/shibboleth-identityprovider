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
import edu.internet2.middleware.shibboleth.resource.FilterSupport;
import edu.internet2.middleware.shibboleth.resource.FilterSupport.RMAppInfo;
import edu.internet2.middleware.shibboleth.serviceprovider.FilterSupportImpl;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderConfig;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderContext;

/**
 * Initialize on request the IdP, SP, and Filter on behalf of a JUnit test.
 * 
 * <p>An instance of this class is created by a JUnit test class, which
 * uses it to initialize and create MockRunner objects for testing the
 * Shibboleth components. This keeps the tests themselves simple.</p>
 * 
 * <p>Look at *.integration.IntegrationTest for an example of use.</p>
 * 
 * @author Howard Gilbert.
 */
public class ShibbolethRunner {
    
    
    public static int SERVER_PORT = 443;
    public static String SERVER_NAME = "idp.example.org";
    public static String SCHEME = "https";
    public static String PROTOCOL = "HTTP/1.1";
    public static String CONTEXT_PATH = "/shibboleth-idp";
    public static String REMOTE_ADDR = "127.0.0.1";
    public static String RESOURCE_CONTEXT_PATH = "/secure";
    public static int RESOURCE_SERVER_PORT = 9443;
    public static String CONTEXT_URL = SCHEME+"://"+SERVER_NAME+CONTEXT_PATH+"/";
    public static String RESOURCE_CONTEXT_URL = SCHEME+"://"+SERVER_NAME+":"+RESOURCE_SERVER_PORT+RESOURCE_CONTEXT_PATH+"/";
    
    
    private static SAMLConfig samlConfig; 

    
    
    /**
     * Initialization logic goes here.
     * <p>Reqires that Log4J already be configured.</p>
     */
    public ShibbolethRunner() {
        
        // Configure SAML to use the MockRunner interface to callback
        // from the SP to the IdP instead of trying to use real HTTP.
        samlConfig = SAMLConfig.instance();
        samlConfig.setDefaultBindingProvider(SAMLBinding.SOAP,"edu.internet2.middleware.shibboleth.runner.MockHTTPBindingProvider" );
    }
 
    
    
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
    
    
    
    /*
     * The SP is represented by an SPContext object and the objects
     * SessionManager, SPConfig, etc. chained off it. The context
     * is initialized and then the main configuration file is read
     * in to create the Config object.
     * 
     * The testing environment doesn't bother with MockRunner objects.
     * The Servlet interface to the SP is a thin layer that only 
     * translates between HTTP/HTML (the Request object) and method
     * calls. So once initialized, it is just as easy to call the
     * SessionManager and FilterSupportImpl directly.
     */
    
    private String spConfigFileName = "/basicSpHome/spconfig.xml";
    /**
     * If you are goint to change the SP Config File
     * do it before calling initServiceProvider.
     * 
     * @param spConfigFileName
     */
    public void setSpConfigFileName(String spConfigFileName) {
        this.spConfigFileName = spConfigFileName;
    }
    
    private static boolean SPinitialized = false; // don't do it twice
    
    /**
     * Load an SP configuration file.
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
    }
    

    
    /*
     * Setup the IdP interface object
     * 
     * The IdP keeps its "context" of cached data and configured 
     * objects internal rather than exposing it as a public object.
     * The IdpTestContext object does the initialization and creates
     * a set of MockRunner object through which the SSO, AA, and 
     * Artifact requests can be generated.
     * 
     * The real IdP objects configure themselves when the Servlet
     * init() method is called. The Configuration file name coded
     * here is passed to the Servlet as a simulated context parameter.
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
    
    public static IdpTestContext idp = null;
    
    /**
     * Initializes the IdP if necessary, then returns a 
     * pointer to the MockRunner interface object
     * @return IdpTestContext with Mockrunner objects
     */
    public IdpTestContext getIdp() {
        if (idp==null) {
            idp = new IdpTestContext();
        }
        return idp;
    }
    
    
    /**
     * Establish initialized IdP and a set of MockRunner objects to
     * process SSO, AA, and Artifact requests.
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
        // The object is created by Mockrunner
        public IdPResponder idpServlet;
        
        /**
         * Construct with the default configuration file
         */
        public IdpTestContext() {
            this(idpConfigFileName);
        }
        
        /**
         * Construct using a specified IdP configuration file.
         */
        public IdpTestContext(String configFileName) {
            
            // ServletContext
            servletContext.setServletContextName("dummy IdP Context");
            servletContext.setInitParameter("IdPConfigFile", configFileName);
            
            
            // Create instance of Filter class, add to chain, call its init()
            // NOTE: The IdP reads its configuration file and initializes
            // itself within this call.
            idpServlet = (IdPResponder) testModule.createServlet(IdPResponder.class);
            resetLoggingLevels();
            
            // Unchanging properties of the HttpServletRequest
            request.setRemoteAddr(REMOTE_ADDR);
            request.setContextPath(CONTEXT_PATH);
            request.setProtocol(PROTOCOL);
            request.setScheme(SCHEME);
            request.setServerName(SERVER_NAME);
            request.setServerPort(SERVER_PORT);
            
        }
        
        /**
         * Set the fields of the request that depend on a suffix,
         * normally SSO, AA, or Artifact
         */
        public void setRequestUrls(String suffix) {
            request.setRequestURI(CONTEXT_URL+suffix);
            request.setRequestURL(CONTEXT_URL+suffix);
            request.setServletPath(CONTEXT_PATH+"/"+suffix);
        }
        
    }

    
    
    
    
    /*
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
    
    
    
    /*
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
     * <p>The SP must be initialized to provide parameters.</p>
     *
     */
    public class AuthenticationFilterContext {
        

        // The Factory creates the Request, Response, Session, etc.
        public WebMockObjectFactory factory = new WebMockObjectFactory();
        
        // The TestModule runs the Servlet and Filter methods in the simulated container
        public ServletTestModule testModule = new ServletTestModule(factory);
        
        // Now simulated Servlet API objects
        public MockServletContext servletContext= new MockServletContext();
        public MockFilterConfig filterConfig= factory.getMockFilterConfig();
        public MockHttpServletResponse response = factory.getMockResponse();
        public MockHttpServletRequest request = factory.getMockRequest();
        
        /*
         * The Missing Manual: There are three types of init-params in
         * the web.xml. One applies to the Context as a whole. The other
         * two are nested inside a <servlet> or <filter> and provide
         * parameters specific to that particular object. If you do
         * a factory.getMockServletContext() you get an object that corresponds
         * to the web.xml configuration itself. However, rather than adding
         * init-param collections to the MockServletConfig and MockFilterConfig,
         * Mockrunner seems to chain a user-created MockServletContext object
         * to them and use its init-params as the parameters fed back to the
         * Filter or Servlet object. So when you see "new MockServletContext()"
         * there is a pretty good reason to expect this will not be used as a
         * real ServletContext but rather as a secondary control block to a 
         * MockFilterConfig or MockServletConfig.
         */
        
        // Filter objects
        private AuthenticationFilter filter;
        
        // SP configuration objects
        private FilterSupport service;
        private RMAppInfo rmAppInfo;

       public AuthenticationFilterContext() {
            
            // ServletContext (argument to Filters and Servlets)
            servletContext.setServletContextName("dummy Servlet Context");
            servletContext.setInitParameter("requireId", ".+/test.+");
            
            // The FilterConfig (argument to Filter init)
            filterConfig.setupServletContext(servletContext);
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
            filter = (AuthenticationFilter) testModule.createFilter(AuthenticationFilter.class);
            
            // Note: if the SP is already initialized, this noops.
            initializeSP();
            
            // Plug an instance of FilterSupportImpl into the Filter
            service = new FilterSupportImpl();
            AuthenticationFilter.setFilterSupport(service);

            // Get our own copy of SP Config info for Assert statements
            rmAppInfo = service.getRMAppInfo("default");

            request.setRemoteAddr(REMOTE_ADDR);
            request.setContextPath(RESOURCE_CONTEXT_PATH);
            request.setProtocol(PROTOCOL);
            request.setScheme(SCHEME);
            request.setServerName(SERVER_NAME);
            request.setServerPort(RESOURCE_SERVER_PORT);
        }
        
        public void setRequestUrls(String suffix) {
            request.setMethod("GET");
            request.setRequestURI(RESOURCE_CONTEXT_URL+suffix);
            request.setRequestURL(RESOURCE_CONTEXT_URL+suffix);
            request.setServletPath(RESOURCE_CONTEXT_PATH+"/"+suffix);
            
        }
    }
    
}
