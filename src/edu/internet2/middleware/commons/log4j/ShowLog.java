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
 * ShowLog.java
 * 
 * Servlet that extracts the ThreadLocal log data from the HttpSession and 
 * returns it to the user's browser.
 * 
 * Dependencies: The session attribute name must match the name used by the Filter.
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
