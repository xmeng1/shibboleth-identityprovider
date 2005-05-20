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

/*
 * ThreadLocalAppender.java
 * 
 * This is a Log4J Appender. You add it to your Log4J configuration just 
 * like any other appender class. However, it doesn't write the log data
 * to one file or socket like the other appenders. It obtains a Writer
 * from a companion class.
 * 
 * We need a companion class to mediate between the Log4J conventions
 * and some Container environment that is dispatching requests to classes
 * using a worker thread pool. Tomcat is a simple example of such a container.
 * This class doesn't know about Tomcat or any other container. 
 * 
 * An object of this class is created whenever an Appender of this
 * type is added (by program or configuration file) to a Log4J logger.
 * There may be more than one "logger" (that is, there may be more
 * than one point in the category name hierarchy of "a.b.c.d" and
 * each with different levels of logging (DEBUG, INFO) to which 
 * thread local request logging is attached. An event will be logged
 * from any of these sources that pass the level criteria. Here, as
 * with the rest of the Log4J environment, the real logging is based
 * on static fields.
 * 
 * However, and this is a key feature of the logic, this "static"
 * environment is ThreadLocal. That means that this "static" data
 * really has a different reference and points to a different Writer
 * in each request processing thread. This is why the superficially
 * "static" value doesn't have to be synchronized.
 * 
 * All ThreadLocalAppenders that share the same companion class name
 * share the same output buffer. To create a separate buffer with
 * separate data, you need both another companion class (which can
 * be modelled on SimpleAppenderContextImpl, but must have a different
 * name) and a separate Filter to load and activate it.
 * 
 * Dependencies: Log4J
 */
package edu.internet2.middleware.commons.log4j;

import java.io.IOException;
import java.io.Writer;

import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.spi.LoggingEvent;

/**
 * Appender that writes to ThreadLocal storage.
 * 
 * <p>This is a standard Log4J appender that just happens to get a Writer
 * every time it wants to log data from a companion class. Actually, this
 * class doesn't know anything about ThreadLocal, but the motivation for
 * this is to maintain separate easy to access logs for each request, and 
 * that can only be accomplied with a ThreadLocal Writer.</p>
 * 
 * <p> Everything here is defined by the Log4J API.</p>
 * 
 * @author Howard Gilbert
 */
public class ThreadLocalAppender extends AppenderSkeleton{

    private ThreadLocalAppenderContext appenderContext = new SimpleAppenderContextImpl();
    
    /**
     * A String property that can be set by the Log4J configuration file 
     * for this Appender to provide the name of a different companion 
     * class implementing the necessary interfaces.
     * <p>
     * Although it is not obvious from any explicit documentation,
     * when Log4J loads an Appender class it uses Bean Introspection
     * to determine any properties of the bean. Subsequent statements
     * in the configuration file (property or xml) can then specify
     * values for the property. In this case, a property named 
     * "LocalContext" can be set to the name of a class that implements
     * the ThreadLocalAppenderContext interface.
     * </p><p>
     * If the property is not set, then "SimpleAppenderContextImpl" is used.</p>
     */
    private String localContext = null;
    public String getLocalContext() {
        return localContext;
    }
    public void setLocalContext(String localContext) {
        this.localContext = localContext;
        try {
            Class c = Class.forName(localContext);
            if (ThreadLocalAppenderContext.class.isAssignableFrom(c)) {
                appenderContext = (ThreadLocalAppenderContext) c.newInstance();
            }
        } catch (ClassNotFoundException e) { 
        } catch (InstantiationException e) {
        } catch (IllegalAccessException e) {
        }
        if (appenderContext==null)
            System.out.println("ThreadLocalAppender cannot load "+localContext);
    }
    /**
     * The main method called by Log4J when an event must be logged.
     * 
     * @param event
     */
    protected void append(LoggingEvent event) {
        if (appenderContext==null)
            return; // No helper class
        Writer logBuffer = appenderContext.getLocalWriter();
        if (logBuffer==null) {
            // If there is no Writer, then we are probably not in a Request.
            // Log4J is static an applies to all the code in all the classes
            // in the source. However, some log statements will appear in 
            // init() methods, or constructors, or background threads. If 
            // you want to log that, you need an ordinary Log4J static 
            // appender. This only logs stuff that happens within the
            // processing path of a Servlet doGet() or similar request.
            return; 
        }
        try {
            logBuffer.write(this.layout.format(event));
        } catch (IOException e) {
            // Best effort, but will not occur with StringWriter.
        }
    }

    public boolean requiresLayout() {
        return true;
    }

    /**
     * Most of the time it is OK to ignore close, but there is some
     * chance that the Writer we are getting is associated with a 
     * File or Socket. So just in case, forward the close on to the
     * Writer.
     */
    public void close() {
        if (appenderContext==null)
            return;
        Writer logBuffer = appenderContext.getLocalWriter();
        if (logBuffer==null)
            return;
        try {
            logBuffer.close();
        } catch (IOException e) {
            // In the common case, this is a StringBuffer that doesn't
            // throw exceptions anyway. Otherwise, this is a best effort.
        }
    }
    

}
