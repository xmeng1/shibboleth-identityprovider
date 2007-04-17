/*
 * Copyright [2006] [University Corporation for Advanced Internet Development, Inc.]
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

package edu.internet2.middleware.shibboleth.idp.profile;

import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.servlet.HttpServletBean;

import edu.internet2.middleware.shibboleth.common.profile.AbstractProfileHandler;

/**
 * Servlet responsible for dispatching incoming requests to the appropriate {@link AbstractProfileHandler}.
 */
public class ProfileRequestDispatcher extends HttpServletBean {

    /** Registered profile handlers. */
    private Map<String, AbstractProfileHandler> profileHandlers;

    /**
     * Gets the profile handlers currently registered.
     * 
     * @return profile handlers currently registered
     */
    public Map<String, AbstractProfileHandler> getProfileHandlers() {
        return profileHandlers;
    }

    /**
     * Sets all the profile handlers to use.
     * 
     * @param handlers the profile handlers to use
     */
    public void setProfileHandlers(Map<String, AbstractProfileHandler> handlers) {
        profileHandlers = handlers;
    }

    /** {@inheritDoc} */
    public void service(HttpServletRequest request, HttpServletResponse response) throws ServletException {
        String path = request.getPathInfo();
        AbstractProfileHandler handler = profileHandlers.get(path);

        if (handler != null) {
            ShibbolethProfileRequest profileReq = new ShibbolethProfileRequest(request);
            ShibbolethProfileResponse profileResp = new ShibbolethProfileResponse(response);
            handler.processRequest(profileReq, profileResp);
        }

        // TODO handle case where there is no registered profile
    }
}