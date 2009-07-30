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

import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContextEntry;
import edu.internet2.middleware.shibboleth.idp.slo.SingleLogoutContext.LogoutInformation;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Iterator;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.opensaml.util.storage.StorageService;

/**
 *
 * @author Adam Lantos  NIIF / HUNGARNET
 */
public class SLOServlet extends HttpServlet {

    private static final long serialVersionUID = -3562061733288921508L;
    // TODO remove once HttpServletHelper does redirects
    private static ServletContext context;
    /** Storage service used to store {@link LoginContext}s while authentication is in progress. */
    private static StorageService<String, LoginContextEntry> storageService;

    /** {@inheritDoc} */
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        
        storageService =
                (StorageService<String, LoginContextEntry>) HttpServletHelper.getStorageService(config.getServletContext());
        context = config.getServletContext();
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        SingleLogoutContext sloContext =
                SingleLogoutContextStorageHelper.getSingleLogoutContext(req);
        if (sloContext != null) {
            SingleLogoutContextStorageHelper.bindSingleLogoutContext(sloContext,
                    storageService, context, req, resp);
        } else {
            resp.sendError(404, "Single Logout servlet can not be called directly");
            return;
        }

        if (req.getParameter("status") != null) { //status query, response is JSON
            resp.setHeader("Cache-Control", "no-cache, must-revalidate");
            resp.setHeader("Pragma", "no-cache");
            PrintWriter writer = resp.getWriter();
            writer.print("[");
            Iterator<SingleLogoutContext.LogoutInformation> it =
                    sloContext.getServiceInformation().values().iterator();
            while (it.hasNext()) {
                LogoutInformation service = it.next();
                writer.print("{\"entityID\":\"");
                writer.print(service.getEntityID());
                writer.print("\",\"logoutStatus\":\"");
                writer.print(service.getLogoutStatus().toString());
                writer.print("\"}");
                if (it.hasNext()) {
                    writer.print(",");
                }
            }
            writer.print("]");
        } else if (req.getParameter("action") != null) { //forward to handler
            req.getRequestDispatcher(sloContext.getProfileHandlerURL()).forward(req, resp);
        } else { //respond with SLO Controller
            resp.setHeader("Cache-Control", "no-cache, must-revalidate");
            resp.setHeader("Pragma", "no-cache");
            req.getRequestDispatcher("/sloController.jsp").forward(req, resp);
        }
    }
}
