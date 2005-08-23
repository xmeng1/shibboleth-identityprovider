package edu.internet2.middleware.shibboleth.serviceprovider;

import java.io.File;

import edu.internet2.middleware.shibboleth.common.Credentials;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderConfig.ApplicationInfo;

public class TestContextInitializer extends SPTestCase {
	
    /**
     * Load the typical sample configuration file from the usual place.
     */
	public void testStandardConfiguration() throws ShibbolethConfigurationException {
		String configFileName = new File("data/spconfig.xml").toURI().toString();
		initServiceProvider(configFileName);
		ServiceProviderConfig config = context.getServiceProviderConfig();
		Credentials credentials = config.getCredentials();
		ApplicationInfo appinfo = config.getApplication("default");
	}
    
	
    /**
     * Try to load a URL that doesn't point to a file.
     */
	public void testBadConfigurationName() {
		String configFileName = new File("data/spconfig-bogus.xml").toURI().toString();;
		try {
            initServiceProvider(configFileName);
            fail();
        } catch (ShibbolethConfigurationException e) {
            // Expected result
        }
	}
}
