/*
 * FilterSupportImpl.java
 * 
 * Provide access to the Filter to configuration information
 * and Session data.
 * 
 * --------------------
 * Copyright 2002, 2004 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
 * [Thats all we have to say to protect ourselves]
 * Your permission to use this code is governed by "The Shibboleth License".
 * A copy may be found at http://shibboleth.internet2.edu/license.html
 * [Nothing in copyright law requires license text in every file.]
 */
package edu.internet2.middleware.shibboleth.target;

import java.util.Map;

import edu.internet2.middleware.shibboleth.common.AAP;
import edu.internet2.middleware.shibboleth.common.AttributeRule;
import edu.internet2.middleware.shibboleth.resource.FilterSupport;
import edu.internet2.middleware.shibboleth.target.ServiceProviderConfig.ApplicationInfo;

/**
 * Provide access from the Filter to the /shibboleth configuration and Sessions.
 * 
 * @author Howard Gilbert
 */
public class FilterSupportImpl implements FilterSupport {
    
    public static ServiceProviderContext context = ServiceProviderContext.getInstance();

    /**
     * Given a Resource URL, go to the RequestMap logic to find an applicationId.
     * 
     * @param url The URL of the Resource presented by the browser
     * @return applicationId string
     */
    public String getApplicationId(String url) {
        ServiceProviderConfig config = context.getServiceProviderConfig();
        String applicationId = config.mapRequest(url);
        return applicationId;
    }
    
    /**
     * Get the "providerId" (site name) of the ServiceProvider
     * 
     * @param applicationId 
     * @return providerId string
     */
    public String getProviderId(String applicationId) {
        ServiceProviderConfig config = context.getServiceProviderConfig();
        ApplicationInfo application = config.getApplication(applicationId);
        String providerId = application.getApplicationConfig().getProviderId();
        return providerId;
    }
    
    /**
     * Get the URL of the local AuthenticationAssertionConsumerServlet.
     * 
     * @param applicationId
     * @return URL string
     */
    public String getShireUrl(String applicationId) {
        ServiceProviderConfig config = context.getServiceProviderConfig();
        ApplicationInfo application = config.getApplication(applicationId);
        String shireUrl = application.getApplicationConfig().getSessions().getShireURL();
        return shireUrl;
    }
    
    /**
     * Get the URL to which the Browser should be initially redirected.
     * 
     * @param applicationId
     * @return URL string
     */
    public String getWayfUrl(String applicationId) {
        ServiceProviderConfig config = context.getServiceProviderConfig();
        ApplicationInfo application = config.getApplication(applicationId);
        String wayfUrl = application.getApplicationConfig().getSessions().getWayfURL();
        return wayfUrl;
    }
    
	/**
	 * Does the requested resource require Shibboleth authentication?
	 * 
	 * @param url  request url
	 * @return     true if Shibboleth is required
	 */
	public boolean isProtected(String url) {
	    // TODO Add some real logic. This is just a placeholder
	    if (url.endsWith("test.txt"))
	        return true;
	    return false;
	}

	/**
	 * Get attributes for this Session 
	 * 
	 * @param sessionId
	 * @param applicationId
	 * @return Map of (attribute,value) pairs
	 */
    public Map /*<String,String>*/ 
    getSessionAttributes(String sessionId, String applicationId) {
        SessionManager sm = context.getSessionManager();
        Session session = 
            sm.findSession(sessionId, applicationId);
        if (session==null)
            return null;
        Map /*<String,String>*/ attributes = SessionManager.mapAttributes(session);
        return attributes;
    }

    /**
     * Map attribute name to pseudo-HTTP-Headers
     * 
     * @param attributeName
     * @param applicationId
     * @return null or Header name string
     */
    public String getHeader(String attributeName, String applicationId) {
        ServiceProviderConfig config = context.getServiceProviderConfig();
        ApplicationInfo application = config.getApplication(applicationId);
        AAP[] providers = application.getAAPProviders();
        for (int i=0;i<providers.length;i++) {
            AAP aap = providers[i];
            AttributeRule rule = aap.lookup(attributeName, null);
            if (rule!=null)
                return rule.getHeader();
        }
        return null;
    }


}
