/*
 * ShowLog.java
 * 
 * Servlet that extracts the ThreadLocal log data from the HttpSession and 
 * returns it to the user's browser.
 * 
 * Dependencies: The session attribute name must match the name used by the Filter.
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
import java.io.Writer;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * @author Howard Gilbert
 */
public class ShowLog extends HttpServlet {
    public static final String REQUESTLOG_ATTRIBUTE = "edu.internet2.middleware.commons.log4j.requestlog";

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        HttpSession session = request.getSession();
        if (session!=null) {
            WrappedLog logBuffer = (WrappedLog) session.getAttribute(REQUESTLOG_ATTRIBUTE);
            response.setContentType("text/plain");
            Writer out = response.getWriter();
            if (logBuffer==null)
                out.write("No Log Data");
            else
                out.write(logBuffer.getLogData());
        }
        
    }
}
