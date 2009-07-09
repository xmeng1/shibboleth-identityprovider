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

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 *
 * @author Adam Lantos  NIIF / HUNGARNET
 */
public class SLOServlet extends HttpServlet {

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        SingleLogoutContext sloContext = SingleLogoutContextStorageHelper.getLoginContext(req);
        
        PrintWriter writer = resp.getWriter();
        writer.print("SLO Request from: ");
        writer.println(sloContext.getRequesterEntityID());
        writer.print("SLO Request ID: ");
        writer.println(sloContext.getRequestSAMLMessageID());
        writer.println("Services");
        for (String entityID : sloContext.getServiceStatus().keySet()) {
            writer.print(entityID);
            writer.print(" logout status is: ");
            writer.println(sloContext.getServiceStatus().get(entityID).toString());
        }
    }

}
