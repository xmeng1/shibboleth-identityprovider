package edu.internet2.middleware.shibboleth.serviceprovider;

import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;

public class TestContextInitializer extends SPTestCase {
	private static ServiceProviderContext context   = ServiceProviderContext.getInstance();
    
    /**
     * Load an SP configuration file.
     * @param configFileName URL format string pointing to configuration file
     * @throws ShibbolethConfigurationException
     */
	public void initServiceProvider(String configFileName) throws ShibbolethConfigurationException{
			ServiceProviderConfig config = new ServiceProviderConfig();
			context.setServiceProviderConfig(config);
			config.loadConfigObjects(configFileName);
	}
	
    /**
     * Load the typical sample configuration file from the usual place.
     */
	public void testStandardConfiguration() throws ShibbolethConfigurationException {
		String configFileName = "file:///usr/local/shibboleth-sp/etc/sp.xml";
		initServiceProvider(configFileName);
	}
    
    /**
     * Try to load a URL that doesn't point to a file.
     */
	public void testBadConfigurationName() {
		String configFileName = "file:///usr/local/shibboleth-sp/etc/spp.xml";
		try {
            initServiceProvider(configFileName);
            fail();
        } catch (ShibbolethConfigurationException e) {
            // Expected result
        }
	}
}
