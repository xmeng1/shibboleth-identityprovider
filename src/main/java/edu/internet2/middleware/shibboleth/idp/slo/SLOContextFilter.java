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
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.opensaml.util.storage.StorageService;

/**
 *
 * @author Adam Lantos  NIIF / HUNGARNET
 */
public class SLOContextFilter implements Filter {

    // TODO remove once HttpServletHelper does redirects
    private static ServletContext context;
    /** Storage service used to store {@link LoginContext}s while authentication is in progress. */
    private static StorageService<String, LoginContextEntry> storageService;

    /** {@inheritDoc} */
    public void init(FilterConfig config) throws ServletException {
        storageService =
                (StorageService<String, LoginContextEntry>) HttpServletHelper.getStorageService(config.getServletContext());
        context = config.getServletContext();
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;
        
        SingleLogoutContext sloContext =
                SingleLogoutContextStorageHelper.getSingleLogoutContext(req);
        if (sloContext != null) {
            //context found in the request, this must be a forward
            SingleLogoutContextStorageHelper.bindSingleLogoutContext(sloContext, storageService, context, req, resp);
        } else {
            sloContext =
                    SingleLogoutContextStorageHelper.getSingleLogoutContext(storageService, context, req);
            SingleLogoutContextStorageHelper.bindSingleLogoutContext(sloContext, req);
        }

        chain.doFilter(request, response);
    }

    public void destroy() {
    }
}
