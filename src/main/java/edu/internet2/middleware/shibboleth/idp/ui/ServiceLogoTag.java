/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.JspWriter;
import javax.servlet.jsp.tagext.BodyContent;

import org.opensaml.samlext.saml2mdui.Logo;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Logo for the SP. */
public class ServiceLogoTag extends ServiceTagSupport {

    /**
     * checkstyle control.
     */
    private static final long serialVersionUID = 6451849117572923712L;

    /** Class logger. */
    private static Logger log = LoggerFactory.getLogger(ServiceLogoTag.class);

    /** what to emit if the jsp has nothing. */
    private static final String DEFAULT_VALUE = "";

    /** what to emit as alt txt if all else fails. */
    private static final String DEFAULT_ALT_TXT = "SP Logo";

    /** Bean storage. Size constraint X */
    private int minWidth;

    /** Bean storage. Size constraint X */
    private int maxWidth = Integer.MAX_VALUE;

    /** Bean storage. Size constraint Y */
    private int minHeight;

    /** Bean storage. Size constraint Y */
    private int maxHeight = Integer.MAX_VALUE;

    /** Bean storage. alt text */
    private String altTxt;

    /**
     * Bean setter.
     * 
     * @param value what to set
     */
    public void setMaxWidth(Integer value) {
        maxWidth = value.intValue();
    }

    /**
     * Bean setter.
     * 
     * @param value what to set
     */
    public void setMinWidth(Integer value) {
        minWidth = value.intValue();
    }

    /**
     * Bean setter.
     * 
     * @param value what to set
     */
    public void setMinHeight(Integer value) {
        minHeight = value.intValue();
    }

    /**
     * Bean setter.
     * 
     * @param value what to set
     */
    public void setMaxHeight(Integer value) {
        maxHeight = value.intValue();
    }

    /**
     * Bean setter.
     * 
     * @param value what to set
     */
    public void setAlt(String value) {
        altTxt = value;
    }

    /**
     * Whether the provided logo fits inside the constraints.
     * 
     * @param logo the logo
     * @return whether it fits the provided max and mins
     */
    private boolean logoFits(Logo logo) {
        return logo.getHeight() <= maxHeight && logo.getHeight() >= minHeight && logo.getWidth() <= maxWidth
                && logo.getWidth() >= minWidth;
    }
    
    /**
     * get an appropriate logo by lanaguage from the UIInfo.
     * @param logos what to look through
     * @return an appropriate logo.
     */
    private String getLogoFromUIInfo(List<Logo> logos) {
        for (String lang : getBrowserLanguages()) {
            // By language first
            for (Logo logo : logos) {
                log.debug("Found logo in UIInfo, language=" + logo.getXMLLang() + " width=" + logo.getWidth()
                        + " height=" + logo.getHeight());
                if (null == logo.getXMLLang() || !logo.getXMLLang().equals(lang) || !logoFits(logo)) {
                    // No language, language mismatch or not fitting
                    continue;
                }
                // Found it
                log.debug("returning logo from UIInfo " + logo.getURL());
                return logo.getURL();
            }
        }
        // Then by no language
        for (Logo logo : getSPUIInfo().getLogos()) {
            log.debug("Found logo in UIInfo, language=" + logo.getXMLLang() + " width=" + logo.getWidth()
                    + " height=" + logo.getHeight());
            if (null == logo.getXMLLang() && logoFits(logo)) {
                // null language and it fits
                log.debug("returning logo from UIInfo " + logo.getURL());
                return logo.getURL();
            }
        }
        return null;
    }

    /**
     * get an appropriate Logo from UIInfo.
     * 
     * @return the URL for a logo
     * 
     */
    private String getLogoFromUIInfo() {

        if (getSPUIInfo() != null && getSPUIInfo().getLogos() != null) {
            
            String result = getLogoFromUIInfo(getSPUIInfo().getLogos());
            
            if (null != result) {
                return result;
            }
            log.debug("No appropriate logo in UIInfo");
        }
        return null;
    }

    /**
     * Find what the user specified for alt txt.
     * 
     * @return the text required
     */
    private String getAltText() {

        //
        // First see what the user tried
        //
        String value = altTxt;
        if (null != value && 0 != value.length()) {
            return value;
        }

        //
        // Try the request
        //
        value = getServiceName();
        if (null != value && 0 != value.length()) {
            return value;
        }

        return DEFAULT_ALT_TXT;
    }

    /**
     * Given the url build an appropriate &lta href=...
     * 
     * @return the contrcuted hyperlink or null
     */
    private String getHyperlink() {
        String url = getLogoFromUIInfo();
        StringBuilder sb;
        Encoder esapiEncoder = ESAPI.encoder();

        if (null == url) {
            return null;
        }

        try {
            URI theUrl = new URI(url);
            String scheme = theUrl.getScheme();

            if (!"http".equals(scheme) && !"https".equals(scheme) && !"mailto".equals(scheme)) {
                log.warn("The logo URL " + url + " contained an invalid scheme");
                return null;
            }
        } catch (URISyntaxException e) {
            //
            // Could not encode
            //
            log.warn("The logo URL " + url + " was not a URL " + e.toString());
            return null;
        }

        String encodedURL = esapiEncoder.encodeForHTMLAttribute(url);
        String encodedAltTxt = esapiEncoder.encodeForHTMLAttribute(getAltText());

        sb = new StringBuilder("<img src=\"");
        sb.append(encodedURL).append('"');
        sb.append(" alt=\"").append(encodedAltTxt).append('"');
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
                    JspWriter ew = bc.getEnclosingWriter();
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
