/*
 * ThreadLocalAppenderContext.java
 * 
 * An interface describing the services provided by the "helper class"
 * that feeds the ThreadLocal Writer to the Log4J ThreadLocalAppender.
 * It also exposes startRequest() and endRequest() methods to anyone
 * managing the gate through which the threadpool request manager 
 * (say Tomcat) dispatches requests (GET or PUT HTTP requests) to an
 * application (a Tomcat context) where you want a separate log file
 * or buffer for every individual request processed.
 * 
 * The default implementation of this interface is provided by the
 * SimpleAppenderContextImpl class.
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

import java.io.Writer;


/**
 * Provide ThreadLocalAppender with a Writer into which to put the log data.
 * 
 * Provide the Request managment layer (Servlet, Servlet Filter, RMI, ...)
 * methods to signal the start and end of a request. After the startRequest
 * the implementing object should have generated a bucket to hold trace and
 * should 
 * 
 * <p>The purpose of ThreadLocal logging is to log activity local to a request
 * in an application server (say a Tomcat Web request). The problem is that
 * such threads never belong to the code that is doing the logging, they 
 * belong to the external container. So what you have to do is load the
 * ThreadLocal reference on entry to the Servlet/EJB/whatever and then
 * clear the pointer before returning to the container. You can't do that
 * if the ThreadLocal variable belongs to the Appender, because the 
 * Appender should, if properly abstracted, only know about log4j. So you
 * have to feed the appender an object (or the name of a class that can
 * create an object) that knows where the ThreadLocal pointer is for this
 * application and can return it. That is what this interface does.</p>
 * 
 * <p>You must create a class, familiar with the environment, that implements
 * the class and passes back either null or a ThreadLocal Writer.
 * The name of this class must be the LocalContext parameter of the
 * ThreadLocalAppender configuration. The class must be in the classpath when
 * the Appender is configured.
 * </p>
 * 
 * @author Howard Gilbert
 */
public interface ThreadLocalAppenderContext {
    
    /**
     * Give the Appender a Writer into which to write data.
     * @return Writer
     */
    Writer getLocalWriter();
    
    /**
     * Called by the request manager (say the Servlet Filter) to 
     * signal the start of a new request. The implementor must 
     * allocate a new Writer to accept data.
     */
    void startRequest();
    
    /**
     * Called by the request manager to signal the end of a request.
     * Returns an IOU that will deliver the log data on request
     * if it is needed (typically when a Servlet wants to display
     * log data to a remote user.)
     * @return WrappedLog object to access log data.
     */
    WrappedLog endRequest();
    
}
