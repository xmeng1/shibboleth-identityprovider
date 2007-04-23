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

package edu.internet2.middleware.shibboleth.idp.session.impl;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import edu.internet2.middleware.shibboleth.common.session.impl.AbstractSession;
import edu.internet2.middleware.shibboleth.idp.session.AuthenticationMethodInformation;
import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;
import edu.internet2.middleware.shibboleth.idp.session.Session;

/**
 * Session information for user logged into the IdP.
 */
public class SessionImpl extends AbstractSession implements Session {
    
    /** Serial version UID. */
    private static final long serialVersionUID = 2927868242208211623L;

    /** The list of methods used to authentictate the user. */
    private List<AuthenticationMethodInformation> authnMethods;

    /** The list of services to which the user has logged in. */
    private Map<String, ServiceInformation> servicesInformation;

    /**
     * Default constructor.
     * 
     * @param presenter IP address of the presenter
     * @param principal principal ID of the user
     */
    public SessionImpl(InetAddress presenter, String principal) {
        super(presenter, principal);

        authnMethods = new ArrayList<AuthenticationMethodInformation>();
        servicesInformation = new HashMap<String, ServiceInformation>();
    }

    /** {@inheritDoc} */
    public List<AuthenticationMethodInformation> getAuthenticationMethods() {
        return authnMethods;
    }
    
    /** {@inheritDoc} */
    public ServiceInformation getServiceInformation(String entityId) {
        return servicesInformation.get(entityId);
    }

    /** {@inheritDoc} */
    public List<ServiceInformation> getServicesInformation() {
        ArrayList<ServiceInformation> info = new ArrayList<ServiceInformation>();
        for(Map.Entry<String, ServiceInformation> entry : servicesInformation.entrySet()){
            info.add(entry.getValue());
        }
        
        return info;
    }
}