/*
 * WrappedLog.java
 * 
 * IOU object for some Log data.
 * 
 * This interface is implemented, for example, by the 
 * SimpleAppenderContextImpl.WrappedStringLog class.
 * 
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

/**
 * Wrapper to abstract the ThreadLocal log storage.
 * 
 * <p>In most cases, the log data will just be a string kept in memory.
 * However, one could imagine it would be a file on disk, or an EhCache
 * hybrid where the last 100 are kept in memory and the overflow of 
 * less recently used are written to disk. So after logging is done, we
 * return this IOU that will fetch the log data later when you want
 * to display it.
 * 
 * @author Howard Gilbert
 */
public interface WrappedLog {
    
    String getLogData();

}
