/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
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

/*
 * FilterSupportImpl.java
 * 
 * Provide access to the Filter to configuration information
 * and Session data.
 */
package edu.internet2.middleware.shibboleth.serviceprovider;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.apache.log4j.Logger;
import org.opensaml.SAMLException;

import x0.maceShibbolethTargetConfig1.SessionInitiatorDocument.SessionInitiator;
import x0.maceShibbolethTargetConfig1.SessionsDocument.Sessions;
import x0Metadata.oasisNamesTcSAML2.IndexedEndpointType;

import edu.internet2.middleware.shibboleth.aap.AAP;
import edu.internet2.middleware.shibboleth.aap.AttributeRule;
import edu.internet2.middleware.shibboleth.resource.FilterSupport;
import edu.internet2.middleware.shibboleth.serviceprovider.ServiceProviderConfig.ApplicationInfo;

/**
 * This class provides the FilterSupport interface for Resource Managers.
 * It can be directly connected to RMs in the same JVM, or it can be
 * wrapped in a Remote or Web Service interface.
 * 
 * @author Howard Gilbert
 */
public class FilterSupportImpl implements FilterSupport {
    
    private static ServiceProviderContext context = ServiceProviderContext.getInstance();
    private static Logger log = Logger.getLogger(ContextListener.SHIBBOLETH_SERVICE);
    
    /**
     * The Resource has been mapped to an ApplicationId. This routine
     * builds a struct (public data field only serializable class)
     * that contains a subset of parameters extracted from the 
     * Application(s) element, which has been turned into an
     * ApplicationInfo object in the config.  
     * 
     * @param applicationId select the SPConfig Application element
     * @return RMAppInfo structure 
     */
    public RMAppInfo getRMAppInfo(String applicationId) {
        RMAppInfo rmdata = new RMAppInfo();
        
        ServiceProviderConfig config = context.getServiceProviderConfig();
        
        ApplicationInfo appinfo = config.getApplication(applicationId);
        Sessions appSessionValues = appinfo.getSessionsConfig();
        
        rmdata.applicationId = applicationId;
        rmdata.providerId = appinfo.getProviderId();
        
        // The deprecated ShireURL has a fully qualified URL
        // The new preferred syntax uses a prefix from HandlerURL 
        // and a suffix from an AssertionConsumerService
        rmdata.handlerUrl = appSessionValues.getShireURL();
        if (rmdata.handlerUrl==null) {
            String handler = appSessionValues.getHandlerURL();
            if (handler!=null) {
                IndexedEndpointType[] assertionConsumerServiceArray = 
                    appSessionValues.getAssertionConsumerServiceArray();
                IndexedEndpointType assertionConsumerService = null;
                if (assertionConsumerServiceArray.length>0) 
                    assertionConsumerService = assertionConsumerServiceArray[0];
                for (int i=0;i<assertionConsumerServiceArray.length;i++) {
                    if (assertionConsumerServiceArray[i].getIsDefault()) {
                        assertionConsumerService = assertionConsumerServiceArray[i];
                    }
                }
                String suffix = assertionConsumerService.getLocation();
                if (suffix!=null)
                    rmdata.handlerUrl= handler+suffix;
                // Ideally, we should now check the generated URL against the
                // Metadata, but current practice doesn't guarantee that the
                // SP has a copy of its own Metadata declaration.
            }
            
        }
        
        // Again there is a deprecated attribute and some new structure
        rmdata.wayfUrl = appSessionValues.getWayfURL(); // deprecated
        SessionInitiator[] sessionInitiatorArray = appSessionValues.getSessionInitiatorArray();
        if (sessionInitiatorArray.length>0) {
            String temp = sessionInitiatorArray[0].getWayfURL();
            if (temp!=null)
                rmdata.wayfUrl = temp;
        }
        
        rmdata.cookieName = appSessionValues.getCookieName();
        rmdata.cookieProperties = appSessionValues.getCookieProps();
        
        /*
         * The mapping of long globally unique Attribute names
         * to shorter alias names and even dummy HTTP headers is done
         * in the AAP part of the configuration. Run through the AAP
         * blocks and turn this into a more usable pair of Maps keyed
         * by attributeid and returning the nickname or header name.
         */
        rmdata.headerToAttribute = new HashMap();
        rmdata.attributeToAlias = new HashMap();
        AAP[] providers = appinfo.getAAPProviders();
        for (int i=0;i<providers.length;i++) {
            AAP aap = providers[i];
            Iterator attributeRules = aap.getAttributeRules();
            while (attributeRules.hasNext()) {
                AttributeRule rule = (AttributeRule) attributeRules.next();
                String name = rule.getName();
                String alias = rule.getAlias();
                String header = rule.getHeader();
                if (header!=null && header.length()!=0)
                    rmdata.headerToAttribute.put(header,name);
                if (alias!=null && alias.length()!=0)
                    rmdata.attributeToAlias.put(name,alias);
           }
         }
        
        
        return rmdata;
    }
    
	/**
	 * From the Session object, return a simple Map of Attributes
     * and values.
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
     * Process a POST or Artifact Assertion presented to the RM and
     * create a Session object from it.
     * 
     * @param sessionData Assertion data
     * @return sessionId string
     */
    public String createSessionFromData(NewSessionData sessionData) {
        String sessionid;
        try {
            sessionid = AssertionConsumerServlet.createSessionFromData(sessionData);
        } catch (SAMLException e) {
        	log.error("Invalid data submitted by RM "+e);
            return null;
        }
        log.info("Session created from data submitted by RM: "+sessionid);
        return sessionid;
    }


     /**
     * Create empty Session so SessionID can be written as a Cookie
     * before redirecting the Browser to the IDP.
     * 
     * @param applicationId
     * @param url The real resource (Target) URL
     * @return SessionId of empty session
     */
    public String createEmptySession(String applicationId, String url) {
        SessionManager sessionManager = context.getSessionManager();
        String id = sessionManager.reserveSession(applicationId,url);
        return id;
    }

    /**
     * The RM presents its context which is then processed through
     * the RequestMap logic. A transformed verion of RequestMap that
     * contains only the subset of the data applicable to this RM
     * is returned in a format that is easy to serialize. 
     */
    public RMConfigData getResourceManagerConfig(String contextRM) {
        ServiceProviderConfig config = context.getServiceProviderConfig();
        
        RMConfigData rmconfig = new RMConfigData();
        
        rmconfig.hostResolutions = config.contextResolutions(contextRM);
        return rmconfig;
    }

}
