/*
 *  Copyright 2009 NIIF Institute.
 * 
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *  under the License.
 */
package edu.internet2.middleware.shibboleth.idp.slo;

import edu.internet2.middleware.shibboleth.idp.profile.saml2.SLOProfileHandler;
import java.io.IOException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.opensaml.xml.util.DatatypeHelper;

/**
 *
 * @author Adam Lantos  NIIF / HUNGARNET
 */
public class LogoutServlet extends HttpServlet {

    private static final long serialVersionUID = -7808054647676905576L;
    /**
     * Front-channel single logout profile handler path.
     */
    private String profileHandlerPath;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        profileHandlerPath = config.getInitParameter("profileHandlerPath");
        if (DatatypeHelper.isEmpty(profileHandlerPath)) {
            throw new ServletException("Required parameter 'profileHandlerPath' is not set.");
        }
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        req.setAttribute(SLOProfileHandler.IDP_INITIATED_LOGOUT_ATTR, true);
        req.getRequestDispatcher(profileHandlerPath).forward(req, resp);
    }
}
