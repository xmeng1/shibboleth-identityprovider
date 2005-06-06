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

package edu.internet2.middleware.shibboleth.serviceprovider;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.UnavailableException;

import org.apache.log4j.FileAppender;
import org.apache.log4j.Layout;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.xml.security.Init;

import edu.internet2.middleware.commons.log4j.ThreadLocalAppender;

/**
 * A ContextListener gets control from the Servlet Container before
 * any Servlets or Filters are loaded. It can perform the earliest 
 * forms of initialization. Commonly, this is used to initialize log
 * files or container systems (such as Spring). Initialization can
 * done here or in the init routines of the Filters and individual
 * Servlets. It is better to do it here logic that is common to all
 * Servlets and Filters since you do not know what order they will
 * be loaded. It is generally a good idea to have one on spec so
 * that you can move logic around as needed.
 */
public class ContextListener implements ServletContextListener {
	

	// Initialization, parsing files, and setting up
	public static final String SHIBBOLETH_INIT = "shibboleth.init";
	private Logger initLogger = Logger.getLogger(SHIBBOLETH_INIT);
	
	// Authentication and Attribute processing, including SAML, Trust, 
	// Metadata, etc. Because the SP doesn't control all the code, it is
	// based on real classnames
	private Logger clientLogger = Logger.getLogger("edu.internet2.middleware");
	private Logger samlLogger = Logger.getLogger("org.opensaml");
	
	// Requests from the Resource Manager only touch the RequestMapper
	// and Session Cache
	public static final String SHIBBOLETH_SERVICE = "shibboleth.service";
	private Logger serviceLogger = Logger.getLogger(SHIBBOLETH_SERVICE);


	public void contextInitialized(ServletContextEvent servletContextEvent) {
		ServletContext servletContext = servletContextEvent.getServletContext();
		Init.init(); // Let XML Security go first
		
		Layout initLayout = new PatternLayout("%d{HH:mm} %-5p %m%n");
		ThreadLocalAppender threadAppender = new ThreadLocalAppender();
		threadAppender.setLayout(initLayout);
		clientLogger.addAppender(threadAppender);
		
		// The init log location is represented as a URL in the web.xml
		// We have to change this int a fully qualified path name
		String initLogUrl = servletContext.getInitParameter("InitializationLog");
		if (initLogUrl!=null)
			try {
				URI initLogURI = new URI(initLogUrl); 
				File initLogFile = new File(initLogURI);
				String logname = initLogFile.getAbsolutePath();
				FileAppender initLogAppender = new FileAppender(initLayout,logname);
				initLogger.addAppender(initLogAppender);
				initLogger.setLevel(Level.DEBUG);
			} catch (URISyntaxException e1) {
				servletContext.log("InitializationLog context parameter is not a valid URL", e1);
			} catch (IOException e1) {
				servletContext.log("InitializationLog context parameter does not point to a valid location",e1);
			}
			
		
		samlLogger.addAppender(threadAppender);
		samlLogger.setLevel(Level.DEBUG);
		
		try {
			ServletContextInitializer.initServiceProvider(servletContext);
		} catch (UnavailableException e) {
			// Do nothing now, Servlet will retry in a few milliseconds
		}
		
	}

	public void contextDestroyed(ServletContextEvent arg0) {
		// Nothing interesting happens at the end
	}

}
