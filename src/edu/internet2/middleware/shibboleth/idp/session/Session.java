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

package edu.internet2.middleware.shibboleth.idp.session;

import java.util.List;

/**
 * Session information for user logged into the IdP.
 */
public interface Session extends edu.internet2.middleware.shibboleth.common.session.Session{

    /**
     * Gets the methods by which the user has authenticated to the IdP.
     * 
     * @return methods by which the user has authenticated to the IdP
     */
    public List<AuthenticationMethodInformation> getAuthenticationMethods();

    /**
     * Gets the services the user has logged in to.
     * 
     * @return services the user has logged in to
     */
    public List<ServiceInformation> getServicesInformation();
}