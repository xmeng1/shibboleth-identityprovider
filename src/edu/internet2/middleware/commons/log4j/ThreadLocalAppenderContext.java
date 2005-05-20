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
 */

package edu.internet2.middleware.commons.log4j;

import java.io.Writer;

/**
 * Provide ThreadLocalAppender with a Writer into which to put the log data.
 * 
 * Provide the Request managment layer (Servlet, Servlet Filter, RMI, ...) methods to signal the start and end of a
 * request. After the startRequest the implementing object should have generated a bucket to hold trace and should
 * 
 * <p>
 * The purpose of ThreadLocal logging is to log activity local to a request in an application server (say a Tomcat Web
 * request). The problem is that such threads never belong to the code that is doing the logging, they belong to the
 * external container. So what you have to do is load the ThreadLocal reference on entry to the Servlet/EJB/whatever and
 * then clear the pointer before returning to the container. You can't do that if the ThreadLocal variable belongs to
 * the Appender, because the Appender should, if properly abstracted, only know about log4j. So you have to feed the
 * appender an object (or the name of a class that can create an object) that knows where the ThreadLocal pointer is for
 * this application and can return it. That is what this interface does.
 * </p>
 * 
 * <p>
 * You must create a class, familiar with the environment, that implements the class and passes back either null or a
 * ThreadLocal Writer. The name of this class must be the LocalContext parameter of the ThreadLocalAppender
 * configuration. The class must be in the classpath when the Appender is configured.
 * </p>
 * 
 * @author Howard Gilbert
 */
public interface ThreadLocalAppenderContext {

	/**
	 * Give the Appender a Writer into which to write data.
	 * 
	 * @return Writer
	 */
	Writer getLocalWriter();

	/**
	 * Called by the request manager (say the Servlet Filter) to signal the start of a new request. The implementor must
	 * allocate a new Writer to accept data.
	 */
	void startRequest();

	/**
	 * Called by the request manager to signal the end of a request. Returns an IOU that will deliver the log data on
	 * request if it is needed (typically when a Servlet wants to display log data to a remote user.)
	 * 
	 * @return WrappedLog object to access log data.
	 */
	WrappedLog endRequest();

}
