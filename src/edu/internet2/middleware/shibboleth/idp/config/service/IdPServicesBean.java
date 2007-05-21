/*
 * Copyright [2007] [University Corporation for Advanced Internet Development, Inc.]
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

package edu.internet2.middleware.shibboleth.idp.config.service;

import java.util.List;

import edu.internet2.middleware.shibboleth.common.config.BaseService;

/**
 * Collection of services loaded by the IdP.
 */
public class IdPServicesBean {

    /** Logging service for the IdP. */
    private IdPLoggingService loggingService;

    /** Serivce components loaded into the IdP. */
    private List<BaseService> services;

    /**
     * Constructor.
     * 
     * @param logging logging service for the IdP
     * @param loadedServices service components loaded into the IdP
     */
    public IdPServicesBean(IdPLoggingService logging, List<BaseService> loadedServices) {
        loggingService = logging;
        services = loadedServices;
    }

    /**
     * Gets the logging service for the IdP.
     * 
     * @return logging service for the IdP
     */
    public IdPLoggingService getLoggingService() {
        return loggingService;
    }

    /**
     * Gets the service components loaded into the IdP.
     * 
     * @return service components loaded into the IdP
     */
    public List<BaseService> getServices() {
        return services;
    }
}