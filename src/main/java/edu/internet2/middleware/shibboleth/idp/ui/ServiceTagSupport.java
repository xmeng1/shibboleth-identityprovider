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

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.jsp.tagext.BodyTagSupport;

import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.samlext.saml2mdui.UIInfo;
import org.opensaml.xml.XMLObject;

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
        StringBuilder sb = new StringBuilder("<a href=\"");
        sb.append(url).append('"');
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
        
        //
        // grab the login context and the RP config mgr.
        //
        loginContext = HttpServletHelper.getLoginContext(HttpServletHelper.getStorageService(application),
                application, request);
        rpConfigMngr = HttpServletHelper.getRelyingPartyConfigurationManager(application);       
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
       
}
