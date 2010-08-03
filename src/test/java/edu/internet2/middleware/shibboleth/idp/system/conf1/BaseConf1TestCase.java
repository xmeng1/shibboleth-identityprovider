package edu.internet2.middleware.shibboleth.idp.system.conf1;


import org.springframework.context.ApplicationContext;

import edu.internet2.middleware.shibboleth.idp.TestCaseBase;

/**
 * Base unit test case for Spring configuration tests.
 */
public abstract class BaseConf1TestCase extends TestCaseBase {
    
    /** Application context containing the loaded IdP configuration. */
    private ApplicationContext appCtx;

    /** {@inheritDoc} */
    protected void setUp() throws Exception {
        super.setUp();
        
        String[] configs = { "/data/conf1/internal.xml", "/data/conf1/service.xml", };
        appCtx = createSpringContext(configs);
    }
    
    /**
     * Gets the application context containing the IdP configuration for the unit tests.
     * 
     * @return application context containing the IdP configuration for the unit tests
     */
    protected ApplicationContext getApplicationContext(){
        return appCtx;
    }
}