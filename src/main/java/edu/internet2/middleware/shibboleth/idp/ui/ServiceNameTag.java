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

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.JspWriter;
import javax.servlet.jsp.tagext.BodyContent;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
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
    
    /** what to emit if the jsp has nothing. */
    private static final String DEFAULT_VALUE = "Unspecified Service Provider";

    @Override
    public int doStartTag() throws JspException {
       
        try {
            String rawServiceName = getServiceName();
            
            Encoder esapiEncoder = ESAPI.encoder();
            
            String serviceName = esapiEncoder.encodeForHTML(rawServiceName);
            
            if (null == serviceName) {
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
                    pageContext.getOut().print(DEFAULT_VALUE);
                }
            } else {
                pageContext.getOut().print(serviceName);
            }
        } catch (IOException e) {
            log.warn("Error generating name");
            throw new JspException("StartTag", e);
        }
        return super.doStartTag();
    }
}
