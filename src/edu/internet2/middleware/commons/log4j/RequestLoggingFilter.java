/*
 * RequestLoggingFilter.java
 * 
 * Configure any Servlet context that you want to trace setting
 * this class as a filter in the WEB-INF/web.xml
 * 
 * 	<filter>
 *		<filter-name>RequestLogFilter</filter-name>
 *		<filter-class>edu.internet2.middleware.commons.log4j.RequestLoggingFilter</filter-class>
 *	</filter>
 * 
 * The default is to use SimpleAppenderContextImpl as the helper class
 * for the Log4J ThreadLocalAppender. If you want to use another
 * class, specify its name in the filter config as
 * 
 *	<init-param>
 *		<param-name>appenderContextClass</param-name>
 *		<param-value>[fill class name in here]</param-value>
 *	</init-param>
 *
 * The name of the class specified here must match the name
 * configured to the LocalContext property of the ThreadLocalAppender
 * in the Log4J configuration file.
 * 
 * This Filter calls the startRequest() and endRequest() methods
 * of the helper class object to start and stop tracing for the 
 * Servlet request. At the end it takes the buffer of data and 
 * saves it to a named attribute of the HttpSession object. 
 * 
 * You can, of course, use this as a model for other code that
 * processes the trace data differently.
 * 
 * Dependencies: Log4J
 * 
 * --------------------
 * Copyright 2002, 2004 
 * Yale University
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
 * Your permission to use this code is governed by "The Shibboleth License".
 * A copy may be found at http://shibboleth.internet2.edu/license.html
 */
package edu.internet2.middleware.commons.log4j;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * @author Howard Gilbert
 */
public class RequestLoggingFilter implements Filter {
    
    private static final String FilterInitParamName = "appenderContextClass";
    public static final String REQUESTLOG_ATTRIBUTE = "edu.internet2.middleware.commons.log4j.requestlog";
    ThreadLocalAppenderContext ctx = new SimpleAppenderContextImpl();

    /**
     * Extract the helper class name init param (if provided) and create an
     * object of the class.
     * 
     * <p>If the class cannot be found or the object cannot be created,
     * print a message but do nothing more.</p>
     */
    public void init(FilterConfig filterConfig) throws ServletException {
        ThreadLocalAppenderContext newctx = null;
	    String appenderContextClassname = filterConfig.getInitParameter(FilterInitParamName);
	    if (appenderContextClassname==null)
	        return;
	    try {
            Class appenderContextClass = Class.forName(appenderContextClassname);
            Object o = appenderContextClass.newInstance();
            if (o instanceof ThreadLocalAppenderContext)
                newctx = (ThreadLocalAppenderContext) o;
        } catch (ClassNotFoundException e) {
        } catch (InstantiationException e) {
        } catch (IllegalAccessException e) {
        }
        if (newctx!=null)
            ctx=newctx;
        else
            System.out.println("appenderContext parameter specified invalid classname");
    }

    /**
     * For every Http request processed through this context (and
     * mapped by the Filter mapping to this filter) enable thread local
     * request logging on the way in and collect the log data on the way out.
     */
    public void doFilter(ServletRequest arg0, ServletResponse arg1, FilterChain chain) throws IOException, ServletException {
        if (!(arg0 instanceof HttpServletRequest)) {
            chain.doFilter(arg0, arg1); // only handle HTTP requests
        }
        HttpServletRequest request = (HttpServletRequest) arg0; 
        HttpServletResponse response = (HttpServletResponse) arg1;
        HttpSession session = request.getSession();
        
        if (ctx==null) {
            chain.doFilter(arg0,arg1); // do the request while logging
            return;
        }
            
        ctx.startRequest(); // start logging
        
        try {    
            chain.doFilter(arg0,arg1); // do the request while logging
        } finally {
            WrappedLog log = ctx.endRequest(); // stop logging, get the data
            
            // Now put the data in a Session attribute
            if (log!=null) {
                if (session!=null) {
                    session.setAttribute(REQUESTLOG_ATTRIBUTE, log);
                }
            }
        }
    }

    /**
     * 
     */
    public void destroy() {
        
    }

}
