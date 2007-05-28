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

import java.util.Timer;

import org.apache.log4j.Logger;
import org.opensaml.log.Level;
import org.opensaml.util.resource.FilesystemResource;
import org.opensaml.util.resource.ResourceChangeWatcher;
import org.opensaml.util.resource.ResourceException;
import org.opensaml.xml.util.DatatypeHelper;

import edu.internet2.middleware.shibboleth.common.log.Log4jConfigFileResourceListener;

/**
 * Logging service for the IdP.
 */
public class IdPLoggingService {

    /** Location of the Log4j configuration file. */
    private FilesystemResource loggingConfiguration;

    /** Timer used to schedule configuration file polling. */
    private Timer taskTimer;

    /**
     * Constructor.
     * 
     * @param timer timer used to schedule configuration file polling
     * @param logConf location, on the filesystem, of the log4j configuration file
     * 
     * @throws ResourceException thrown if the given configuration file does not exist
     */
    public IdPLoggingService(Timer timer, String logConf) throws ResourceException {
        taskTimer = timer;
        loggingConfiguration = new FilesystemResource(DatatypeHelper.safeTrimOrNullString(logConf));
        if (!loggingConfiguration.exists()) {
            throw new ResourceException("Logging configuration file does not exist: "
                    + loggingConfiguration.getLocation());
        }
    }

    /**
     * Initializes the logging service.
     * 
     * @throws ResourceException thrown if logging configuration file does not exist
     */
    public void initialize() throws ResourceException {
        ResourceChangeWatcher configurationWatcher = new ResourceChangeWatcher(loggingConfiguration, 1000 * 60);
        configurationWatcher.getResourceListeners().add(new Log4jConfigFileResourceListener());
        taskTimer.schedule(configurationWatcher, 0, configurationWatcher.getPollingFrequency());
        Logger log = Logger.getLogger(IdPLoggingService.class);
        log.log(Level.CRITICAL, "Logging service initialized");
    }

    /**
     * Gets the location of the logging configuration file.
     * 
     * @return location of the logging configuration file
     */
    public String getLoggingConfigurationLocation() {
        return loggingConfiguration.getLocation();
    }
}