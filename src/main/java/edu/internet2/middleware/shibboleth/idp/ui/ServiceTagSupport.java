/*
 * Licensed to the University Corporation for Advanced Internet Development, Inc.
 * under one or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information regarding
 * copyright ownership. The ASF licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.idp.ui;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.jsp.tagext.BodyTagSupport;

import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.LocalizedString;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.ServiceName;
import org.opensaml.samlext.saml2mdui.DisplayName;
import org.opensaml.samlext.saml2mdui.UIInfo;
import org.opensaml.xml.XMLObject;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;


/**
 * Display the serviceName.
 * 
 * This is taken in order
 *  1) From the mdui
 *  2) AttributeConsumeService
 *  3) HostName from the EntityId
 *  4) EntityId.
 */
public class ServiceTagSupport extends BodyTagSupport{

    /**
     * checkstyle requires this serialization info.
     */
    private static final long serialVersionUID = 7988646597267865255L;
    
    /** Class logger. */
    private static Logger log = LoggerFactory.getLogger(ServiceTagSupport.class);

    /** Bean storage. class reference*/
    private String cssClass;
    /** Bean storage. id reference*/
    private String cssId;
    /** Bean storage. style reference*/
    private String cssStyle;

    /** Bean setter.
     * @param value what to set
     */
    public void setCssClass(String value) {
        cssClass = value;
    }
    /** Bean setter.
     * @param value what to set
     */
    public void setCssId(String value) {
        cssId = value;
    }

    /** Bean setter.
     * @param value what to set
     */
    public void setCssStyle(String value) {
        cssStyle = value;
    }

    /**
     * Add the class and Id if present.
     * @param sb the stringbuilder to asdd to.
     */
    protected void addClassAndId(StringBuilder sb) {
        if (cssClass != null) {
            sb.append(" class=\"").append(cssClass).append('"');
        }
        if (cssId != null) {
            sb.append(" id=\"").append(cssId).append('"');
        }
        if (cssStyle != null) {
            sb.append(" style=\"").append(cssStyle).append('"');
        }
    }
    
    /**
     * build a hyperlink from the parameters.
     * @param url the URL
     * @param text what to embed
     * @return the hyperlink.
     */
    protected String buildHyperLink(String url, String text) {
        String encodedUrl;
        Encoder esapiEncoder = ESAPI.encoder();
       
        try {
            URI theUrl = new URI(url);
            String scheme = theUrl.getScheme();

            if (!"http".equals(scheme) && !"https".equals(scheme) && !"mailto".equals(scheme)) {
                log.warn("The URL " + url + " contained an invalid scheme");
                return "";
            }
            encodedUrl = esapiEncoder.encodeForHTMLAttribute(url);
        } catch (URISyntaxException e) {
            // 
            // It wasn't an URI.
            //
            log.warn("The URL " + url + " was invalid: " + e.toString());
            return "";
        }
        
        StringBuilder sb = new StringBuilder("<a href=\"");
        sb.append(encodedUrl).append('"');
        addClassAndId(sb);
        sb.append(">").append(text).append("</a>");
        return sb.toString();
    }
    
    /**
     * Get the EntityDescriptor for the relying party.
     * @return the SPs EntityDescriptor
     */
    protected EntityDescriptor getSPEntityDescriptor() {
        LoginContext loginContext;
        HttpServletRequest request;
        ServletContext application;
        RelyingPartyConfigurationManager rpConfigMngr;
        EntityDescriptor spEntity;
        
        //
        // Populate up those things that jsp gives us.
        //
        request = (HttpServletRequest) pageContext.getRequest();
        application = pageContext.getServletContext();
        
        if (request == null || application == null) {
           return null;
        }
        //
        // grab the login context and the RP config mgr.
        //
        loginContext = HttpServletHelper.getLoginContext(HttpServletHelper.getStorageService(application),
                application, request);
        rpConfigMngr = HttpServletHelper.getRelyingPartyConfigurationManager(application);
        if (loginContext == null || rpConfigMngr == null) {
            return null;
        }
        spEntity = HttpServletHelper.getRelyingPartyMetadata(loginContext.getRelyingPartyId(), rpConfigMngr);

        return spEntity;
    }
    /**
     * Traverse the SP's EntityDescriptor and pick out the UIInfo.
     * @return the first UIInfo for the SP.
     */
    protected UIInfo getSPUIInfo() {
        EntityDescriptor spEntity = getSPEntityDescriptor();
        Extensions exts;
        
        if (null == spEntity) {
            //
            // all done
            //
            return null;
        }

        for (RoleDescriptor role:spEntity.getRoleDescriptors(SPSSODescriptor.DEFAULT_ELEMENT_NAME)) {
            exts = role.getExtensions();
            if (exts != null) {
                for (XMLObject object:exts.getOrderedChildren()) {
                    if (object instanceof UIInfo) {
                        return (UIInfo) object;
                    }
                }
            }
        }
        return null;
    }
            
    /**
     * Pluck the language from the browser.
     * @return the two letter language
     */
    protected String getBrowserLanguage() {
        HttpServletRequest request;
        request = (HttpServletRequest) pageContext.getRequest();
        
        return request.getLocale().getLanguage();
    }
    /**
     * If the entityId can look like a host return that otherwise the string.
     * @return either the host or the entityId.
     */
    private String getNameFromEntityId() {
        EntityDescriptor sp = getSPEntityDescriptor();
        
        if (null == sp) {
            log.debug("No relying party, nothing to display");
            return null;
        }

        try {
            URI entityId = new URI(sp.getEntityID());
            String scheme = entityId.getScheme();

            if ("http".equals(scheme) || "https".equals(scheme)) {
                return entityId.getHost(); 
            }
        } catch (URISyntaxException e) {
            // 
            // It wasn't an URI.  return full entityId.
            //
            return sp.getEntityID();
        }
        //
        // not a URL return full entityID
        //
        return sp.getEntityID();
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
        EntityDescriptor sp = getSPEntityDescriptor();
        
        if (null == sp) {
            log.warn("No relying party, nothing to display");
            return null;
        }

        roles = sp.getRoleDescriptors(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
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
    protected String getServiceName() {
        String result;
        //
        // First look for MDUI
        //
        if (getSPEntityDescriptor() == null) {
            log.debug("No relying party, nothing to display");
            return null;
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
    

}
