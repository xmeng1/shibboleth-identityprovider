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

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import edu.internet2.middleware.shibboleth.common.profile.BaseServletProfileRequestDispatcher;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;

/**
 * Servlet responsible for dispatching incoming shibboleth requests to the appropriate profile handler.
 */
public class ShibbolethProfileRequestDispatcher extends BaseServletProfileRequestDispatcher {

    /** Serial version UID. */
    private static final long serialVersionUID = -3939942569721369334L;

    /** {@inheritDoc} */
    protected ProfileRequest getProfileRequest(ServletRequest request) {
        return new ShibbolethProfileRequest((HttpServletRequest) request);
    }

    /** {@inheritDoc} */
    protected ProfileResponse getProfileResponse(ServletResponse response) {
        return new ShibbolethProfileResponse((HttpServletResponse) response);
    }
}