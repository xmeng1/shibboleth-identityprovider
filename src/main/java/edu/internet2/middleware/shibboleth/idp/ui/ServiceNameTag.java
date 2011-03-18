/*
 * Copyright 2011 University Corporation for Advanced Internet Development, Inc.
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

package edu.internet2.middleware.shibboleth.idp.ui;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import javax.servlet.jsp.JspException;

import org.opensaml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml2.metadata.LocalizedString;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.ServiceName;
import org.opensaml.samlext.saml2mdui.DisplayName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Display the serviceName.
 * 
 * This is taken in order
 *  1) From the mdui
 *  2) AttributeConsumeService
 *  3) HostName from the EntityId
 *  4) EntityId.
 */
public class ServiceNameTag extends ServiceTagSupport {

    /** checkstyle requires one of these. */
    private static final long serialVersionUID = 8883158293402992407L;
    /** Class logger. */
    private static Logger log = LoggerFactory.getLogger(ServiceNameTag.class);
    
    /**
     * If the entityId can look like a host return that otherwise the string.
     * @return either the host or the entityId.
     */
    private String getNameFromEntityId() {
        try {
            URI entityId = new URI(getSPEntityDescriptor().getEntityID());
            String scheme = entityId.getScheme();

            if ("http".equals(scheme) || "https".equals(scheme)) {
                return entityId.getHost(); 
            }
        } catch (URISyntaxException e) {
            // 
            // It wasn't an URI.  return full entityId.
            //
            return getSPEntityDescriptor().getEntityID();
        }
        //
        // not a URL return full entityID
        //
        return getSPEntityDescriptor().getEntityID();
    }
    
    /** 
     * look at &lt;Uiinfo&gt; if there and if so look for appropriate name.
     * @return null or an appropriate name
     */
    private String getNameFromUIInfo() {
        String lang = getBrowserLanguage();

        if (getSPUIInfo() != null) {
            for (DisplayName name:getSPUIInfo().getDisplayNames()) {
                if (log.isDebugEnabled()){
                    log.debug("Found name in UIInfo, language=" + name.getXMLLang());
                }
                if (name.getXMLLang().equals(lang)) {
                    //
                    // Found it
                    //
                    if (log.isDebugEnabled()){
                        log.debug("returning name from UIInfo " + name.getName().getLocalString());
                    }
                    return name.getName().getLocalString();
                }
            }
            if (log.isDebugEnabled()){
                log.debug("No name in UIInfo");
            }            
        }
        return null;
    }

    /**
     * look for an &ltAttributeConsumeService&gt and if its there look for an appropriate name.
     * @return null or an appropriate name
     */
    private String getNameFromAttributeConsumingService(){
        String lang = getBrowserLanguage();
        List<RoleDescriptor> roles;
        AttributeConsumingService acs = null;

        roles = getSPEntityDescriptor().getRoleDescriptors(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        if (!roles.isEmpty()) {
            SPSSODescriptor spssod = (SPSSODescriptor) roles.get(0);
            acs = spssod.getDefaultAttributeConsumingService();
        }
        if (acs != null) {
            for (ServiceName name:acs.getNames()) {
                LocalizedString localName = name.getName();
                if (log.isDebugEnabled()){
                    log.debug("Found name in AttributeConsumingService, language=" + localName.getLanguage());
                }
                if (localName.getLanguage().equals(lang)) {
                    if (log.isDebugEnabled()){
                        log.debug("returning name from AttributeConsumingService " + name.getName().getLocalString());
                    }
                    return localName.getLocalString();
                }
            }
            if (log.isDebugEnabled()){
                log.debug("No name in AttributeConsumingService");
            }            
        }        
        return null;
    }
    
    /**
     * Get the identifier for the service name as per the rules above.
     * @return something sensible for display.
     */
    private String getServiceName() {
        String result;
        //
        // First look for MDUI
        //
        if (getSPEntityDescriptor() == null) {
            log.warn("No relying party, nothing to display");
            return "";
        }
        //
        // Look at <UIInfo>
        //
        result = getNameFromUIInfo();
        if (result != null) {
            return result;
        }
        
        //
        // Otherwise <AttributeConsumingService>
        //
        result = getNameFromAttributeConsumingService();
        if (result != null) {
            return result;
        }
        
        //
        // Or look at the entityName
        //
        return getNameFromEntityId();
    }
    
    @Override
    public int doStartTag() throws JspException {
       
        try {
            pageContext.getOut().print(getServiceName());
        } catch (IOException e) {
            log.warn("Error generating name");
            throw new JspException("StartTag", e);
        }
        return super.doStartTag();
    }
}
