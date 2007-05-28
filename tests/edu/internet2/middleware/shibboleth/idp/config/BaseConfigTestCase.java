package edu.internet2.middleware.shibboleth.idp.config;


import java.util.ArrayList;
import java.util.List;

import org.opensaml.util.resource.ClasspathResource;
import org.opensaml.util.resource.Resource;
import org.opensaml.util.resource.ResourceException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.GenericApplicationContext;

import edu.internet2.middleware.shibboleth.common.BaseTestCase;
import edu.internet2.middleware.shibboleth.common.config.SpringConfigurationUtils;

/**
 * Base unit test case for Spring configuration tests.
 */
public class BaseConfigTestCase extends BaseTestCase {

    /** Configuration resources to be loaded for all unit tests. */
    private List<Resource> configResources;

    /** {@inheritDoc} */
    protected void setUp() throws Exception {
        configResources = new ArrayList<Resource>();
    }

    /**
     * Creates a Spring application context from the instance defined config resources.
     * 
     * @return the created context
     * 
     * @throws ResourceException thrown if there is a problem reading the configuration resources
     */
    protected ApplicationContext createSpringContext() throws ResourceException {
        return createSpringContext(configResources);
    }

    /**
     * Creates a Spring application context from the given configuration and any instance registered configurations.
     * 
     * @param config spring configuration file to be located on the classpath
     * 
     * @return the configured spring context
     * 
     * @throws ResourceException thrown if the given resources can not be located
     */
    protected ApplicationContext createSpringContext(String config) throws ResourceException {
        String[] configs = new String[1];
        configs[0] = config;
        return createSpringContext(configs);
    }

    /**
     * Creates a Spring application context from the given configurations and any instance registered configurations.
     * 
     * @param configs spring configuration files to be located on the classpath
     * 
     * @return the configured spring context
     * 
     * @throws ResourceException thrown if the given resources can not be located
     */
    protected ApplicationContext createSpringContext(String[] configs) throws ResourceException {
        ArrayList<Resource> resources = new ArrayList<Resource>();
        resources.addAll(configResources);
        if (configs != null) {
            for (String config : configs) {
                resources.add(new ClasspathResource(config));
            }
        }

        return createSpringContext(resources);
    }

    /**
     * Creates a Spring context from the given resources.
     * 
     * @param configs context configuration resources
     * 
     * @return the created context
     * 
     * @throws ResourceException thrown if there is a problem reading the configuration resources
     */
    protected ApplicationContext createSpringContext(List<Resource> configs) throws ResourceException {
        GenericApplicationContext gContext = new GenericApplicationContext();
        SpringConfigurationUtils.populateRegistry(gContext, configs);
        gContext.refresh();
        return gContext;
    }
}