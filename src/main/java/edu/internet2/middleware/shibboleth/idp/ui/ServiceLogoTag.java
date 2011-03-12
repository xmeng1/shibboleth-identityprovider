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

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.JspWriter;
import javax.servlet.jsp.tagext.BodyContent;

import org.opensaml.samlext.saml2mdui.Logo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**Logo for the SP.*/
public class ServiceLogoTag extends ServiceTagSupport {

    /**
     * checkstype control.
     */
    private static final long serialVersionUID = 6451849117572923712L;
    /** Class logger. */
    private static Logger log = LoggerFactory.getLogger(ServiceLogoTag.class);
    /** what to emit if the jsp has nothing. */
    private static final String DEFAULT_VALUE = "";

    /** Bean storage. Size constraint X */
    private int minWidth;
    /** Bean storage. Size constraint X */
    private int maxWidth = Integer.MAX_VALUE;
    /** Bean storage. Size constraint Y */
    private int minHeight;
    /** Bean storage.  Size constraint Y */
    private int maxHeight = Integer.MAX_VALUE;

    /** Bean setter.
     * @param value what to set
     */
    public void setMaxWidth(Integer value) {
        maxWidth = value.intValue();
    }
    /** Bean setter.
     * @param value what to set
     */
    public void setMinWidth(Integer value) {
        minWidth = value.intValue();
    }
    /** Bean setter.
     * @param value what to set
     */
    public void setMinHeight(Integer value) {
        minHeight = value.intValue();
    }
    /** Bean setter.
     * @param value what to set
     */
    public void setMaxHeight(Integer value) {
        maxHeight = value.intValue();
    }

    /**
     * Whether the provided logo fits inside the constraints.
     * @param logo the logo
     * @return whether it fits the provided max and mins
     */
    private boolean logoFits(Logo logo) {
        return logo.getHeight() <= maxHeight && logo.getHeight() >= minHeight &&
               logo.getWidth() <= maxWidth && logo.getWidth() >= minWidth;
    }
    
    /**
     * get an appropriate Logo from UIInfo.
     * @return the URL for a logo
     */
    private String getLogoFromUIInfo() {
        String lang = getBrowserLanguage();

        if (getSPUIInfo() != null && getSPUIInfo().getDescriptions() != null) {
            for (Logo logo:getSPUIInfo().getLogos()) {
                if (log.isDebugEnabled()){
                    log.debug("Found logo in UIInfo, language=" + logo.getXMLLang() + 
                            " width=" + logo.getWidth() + " height=" +logo.getHeight());
                }
                if (null != logo.getXMLLang() && !logo.getXMLLang().equals(lang)) {
                    //
                    // there is a language and its now what we want
                    continue;
                }
                if (!logoFits(logo)) {
                    //
                    // size out of range
                    //
                    continue;
                }
                //
                // Found it
                //
                if (log.isDebugEnabled()) {
                    log.debug("returning logo from UIInfo " + logo.getURL());
                }
                return logo.getURL();
            }
            if (log.isDebugEnabled()){
                log.debug("No appropriate logo in UIInfo");
            }            
        }
        return null;
    }

    /**
     * Given the url build an appropriate &lta href=...
     * @return the contrcuted hyperlink or null
     */
    private String getHyperlink() {
        String url = getLogoFromUIInfo();
        StringBuilder sb;
        
        if (null == url) {
            return null;
        }
        sb = new StringBuilder("<img src=\"");
        sb.append(url).append('"');
        addClassAndId(sb);
        sb.append("/>");
        return sb.toString();
    }
    
    @Override
    public int doEndTag() throws JspException {
       
        String result = getHyperlink();
        
        try {
            if (null == result) {
                BodyContent bc = getBodyContent();
                boolean written = false;
                if (null != bc) {
                    JspWriter ew= bc.getEnclosingWriter();
                    if (ew != null) {
                        bc.writeOut(ew);
                        written = true;
                    }
                }
                if (!written) {
                    //
                    // No value provided put in our own hardwired default
                    //
                    pageContext.getOut().print(DEFAULT_VALUE);
                }
            } else {
                pageContext.getOut().print(result);
            }
        } catch (IOException e) {
            log.warn("Error generating Description");
            throw new JspException("EndTag", e);
        }
        return super.doEndTag();
    }
}
