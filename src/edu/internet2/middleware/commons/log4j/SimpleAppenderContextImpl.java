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
 * SimpleAppenderContext.java
 * 
 * A TheadLocalAppenderContext implementation class serves as the 
 * meeting point between a particular instance of ThreadLocalAppender
 * in a Log4J configuration and a particular thread pool request 
 * dispatcher (such as a Tomcat application context). 
 * 
 * In this simple case, the ThreadLocal reference is held in a 
 * static variable in this class, and it points to a StringWriter.
 * 
 * The ThreadLocalAppender is configured (or defaults since this
 * is the default value) through the LocalContext property. Set 
 * that property in the Log4J configuration file with the name of 
 * a class that implements ThreadLocalAppenderContext. 
 * 
 * The request container is also configured with or default do the
 * name of this class. It calls startRequest() when a new request
 * arrives and endRequest() before returning from request processing.
 * An example is the RequestLoggingFilter that makes these calls just
 * before and just after chaining a Servlet GET or POST request on to
 * the next Filter/Servlet in the processing chain.
 * 
 * What ties things together is the name of this class, and the 
 * fact that the ThreadLocal variable is static in this class. So
 * if you want two differently configured ThreadLocalAppenders to share
 * the same JVM ClassLoader, then you have to create two different classes
 * with two different names and configure at least one new name as the
 * Log4J Appender property or the Filter initialization parameter.
 * 
 * Note: The ThreadLocalAppender creates one object of this class.
 * The RequestLoggingFilter creates a separate object. The two
 * objects share only the static variable. Do not make the 
 * mistake of assuming that the Filter and log share the same
 * object.
 */
package edu.internet2.middleware.commons.log4j;

import java.io.StringWriter;
import java.io.Writer;


/**
 * @author Howard Gilbert
 */
public class SimpleAppenderContextImpl 
	implements ThreadLocalAppenderContext {
    
    private static ThreadLocal localWriterReference = new ThreadLocal();

    /**
     * @return Null or the Writer for the current thread.
     */
    public Writer getLocalWriter() {
        return (Writer) localWriterReference.get();
    }

    /**
     * Called to signal the start of Request processing for this thread.
     */
    public void startRequest() {
        localWriterReference.set(new StringWriter());
    }

    /**
     * Called to signal the end of Request processing. Return log data
     * and null out the Writer to stop collecting data.
     * 
     * @return A wrapped String containing the log data.
     */
    public WrappedLog endRequest() {
        StringWriter stringWriter =(StringWriter) localWriterReference.get();
        if (stringWriter==null)
            return null;
        String logdata = stringWriter.toString();
        localWriterReference.set(null);
        return new WrappedStringLog(logdata);
    }
    
    
    /**
     * The log Writer could be a file or WebDav network store. So
     * the log data could be a String, or a file name, or a URL.
     * This class handles the simple String case.
     * @author Howard Gilbert
     */
    static class WrappedStringLog implements WrappedLog {
        
        String logdata;
        
        WrappedStringLog(String logdata) {
            this.logdata=logdata;
            
        }
        
        public String getLogData() {
            return logdata;
        }
        
    }

}
