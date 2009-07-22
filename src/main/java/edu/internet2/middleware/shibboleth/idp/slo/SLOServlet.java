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

import edu.internet2.middleware.shibboleth.common.session.SessionManager;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContextEntry;
import edu.internet2.middleware.shibboleth.idp.profile.IdPProfileHandlerManager;
import edu.internet2.middleware.shibboleth.idp.session.Session;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import java.io.IOException;
import java.io.PrintWriter;
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

    private static final long serialVersionUID = -6038945519457268089L;
    // TODO remove once HttpServletHelper does redirects
    private static ServletContext context;
    /** Storage service used to store {@link LoginContext}s while authentication is in progress. */
    private static StorageService<String, LoginContextEntry> storageService;
    /** Profile handler manager. */
    private IdPProfileHandlerManager handlerManager;
    /** Session manager. */
    private SessionManager<Session> sessionManager;

    /** {@inheritDoc} */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        handlerManager =
                HttpServletHelper.getProfileHandlerManager(config.getServletContext());
        sessionManager =
                HttpServletHelper.getSessionManager(config.getServletContext());
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
            //TODO when to bind permanently
            SingleLogoutContextStorageHelper.bindSingleLogoutContext(sloContext,
                    storageService, context, req, resp);
        } else {
            sloContext =
                    SingleLogoutContextStorageHelper.getSingleLogoutContext(storageService, context, req);
        }

        PrintWriter writer = resp.getWriter();
        writer.print("SLO Request from: ");
        writer.println(sloContext.getRequesterEntityID());
        writer.print("SLO Request ID: ");
        writer.println(sloContext.getRequestSAMLMessageID());
        writer.println("Services");
        for (String entityID : sloContext.getServiceInformation().keySet()) {
            writer.print(entityID);
            writer.print(" logout status is: ");
            writer.println(sloContext.getServiceInformation().get(entityID).getLogoutStatus().toString());
        }
    }
}
