/*
 * ServletContextInitializer.java
 * 
 * Each application in a Servlet Container (a Java Web server like Tomcat)
 * occupies its own subdirectory, has its own ClassLoader, and owns a 
 * collection of objects and classes that are collectively its "Context".
 * 
 * It is not entirely predictable what initialization method will be 
 * called first (maybe a Filter, maybe a Servlet, it depends on the 
 * way web.xml is coded and processed). Some objects may be marked to
 * preload, and some may be loaded when first called.
 * 
 * However, the ServiceProviderContext must be initialzed just once,
 * and it must be initialized before any other ServiceProvider methods
 * are called. So this static class does the job. It can be called from
 * any init() type method in any filter or servlet, and it can be called
 * from the static initialization method of any other class loaded by the
 * container configuration.
 * 
 * The gotcha is that the file location of the configuration file may be
 * a parameter specified in the web.xml file. Code provided here will
 * handle the normal cases where the Servlet or Filter intializes it and
 * the web.xml parameter is found through the ServletContext object. If 
 * you want to use ServiceProvider methods earlier than that, and do not
 * have access to a ServletContext, then you have to modify this class
 * to find the parameter someplace else (say in the server.xml file).
 * Of course, if you initialize the Service Provider classes from 
 * the server's environment instead of the /shibboleth context environment,
 * then the shibboleth JAR files have to be in the server's parent classpath
 * (example: {Tomcat}/common/lib) rather than just in the /shibboleth/WEB-INF/lib. 
 * 
 * As with Servlet and Filter classes, this class knows about javax.servlet.* 
 * objects that other shibboleth classes are not allowed to reference.
 * 
 * --------------------
 * Copyright 2002, 2004 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
 * [Thats all we have to say to protect ourselves]
 * Your permission to use this code is governed by "The Shibboleth License".
 * A copy may be found at http://shibboleth.internet2.edu/license.html
 * [Nothing in copyright law requires license text in every file.]
 */
package edu.internet2.middleware.shibboleth.serviceprovider;

import javax.servlet.ServletContext;
import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;

import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;


/**
 * @author Howard Gilbert
 */
public class ServletContextInitializer {
	
	private static Logger log = Logger.getLogger(ServletContextInitializer.class.getName());
	private static ServiceProviderContext context   = ServiceProviderContext.getInstance();

	public static boolean initialized = false;
	
	public static synchronized void initServiceProvider(ServletContext scontext) 
		throws UnavailableException{
		
		if (initialized)
			return;
		
		try {
			log.info("Initializing Service Provider.");
			
			ServiceProviderConfig config = new ServiceProviderConfig();
			context.setServiceProviderConfig(config);
			
			// could config.addOrReplaceXXXImplementor()

			String configFileName = getTargetConfigFile(scontext);
			config.loadConfigObjects(configFileName);
			
			// could config.addOrReplaceXXXImplementor()
			
			context.setServiceProviderConfig(config);

			log.info("Service Provider initialization complete.");

		} catch (ShibbolethConfigurationException ex) {
			context.setFatalErrors(true);
			log.fatal("Service Provider runtime configuration error.  Please fix and re-initialize. Cause: " + ex);
			throw new UnavailableException("Assertion Consumer Service failed to initialize.");
		}
		initialized = true;
	}
	
	/**
	 * Return name of target's XML configuration file from
	 *  TargetConfigFile parameter of WEB-INF/web.xml, or
	 *  default string
	 * 
	 * @param ServletContext or null 
	 * @return String filename
	 */
	private static String getTargetConfigFile(ServletContext scontext) {
	    
		if (scontext!=null) {
			String servletparm = scontext.getInitParameter("TargetConfigFile");
			if (servletparm != null) {
				return servletparm;
			}
		}

		return "/conf/shibboleth.xml";
		
	}

    /**
     * Initialization specific to processing a request
     * @param request
     * @param response
     */
    public static void beginService(
            HttpServletRequest request, 
            HttpServletResponse response) {
       
        String ipaddr = request.getRemoteAddr();
        RequestTracker requestTracker = new RequestTracker();
        requestTracker.setIpaddr(ipaddr);
        context.setRequestContext(requestTracker);
        
    }

    /**
     * Cleanup specific to a processing a request
     * @param request
     * @param response
     */
    public static void finishService(
            HttpServletRequest request, 
            HttpServletResponse response) {
        RequestTracker requestContext = context.getRequestContext();
        context.setRequestContext(null);
        String ipaddr = requestContext.getIpaddr();
        HttpSession session = request.getSession();
    }

}
