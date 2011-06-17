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

package edu.internet2.middleware.shibboleth.idp.config.profile.authn;

import javax.xml.namespace.QName;

import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.idp.config.profile.ProfileHandlerNamespaceHandler;

/**
 * Spring bean definition parser for previous session authentication handlers.
 */
public class PreviousSessionLoginHandlerBeanDefinitionParser extends AbstractLoginHandlerBeanDefinitionParser {

    /** Schema type. */
    public static final QName SCHEMA_TYPE = new QName(ProfileHandlerNamespaceHandler.NAMESPACE, "PreviousSession");

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(PreviousSessionLoginHandlerBeanDefinitionParser.class);

    /** {@inheritDoc} */
    protected Class getBeanClass(Element arg0) {
        return PreviousSessionLoginHandlerFactoryBean.class;
    }

    /** {@inheritDoc} */
    protected void doParse(Element config, BeanDefinitionBuilder builder) {
        super.doParse(config, builder);

        if (config.hasAttributeNS(null, "servletPath")) {
            log.warn("The 'servletPath' configuration option has been deprecated and is no longer supported.");
        }
        
        if (config.hasAttributeNS(null, "supportsPassiveAuthentication")) {
            log.warn("The 'supportsPassiveAuthentication' configuration option has been deprecated and is no longer supported.");
        }

        if (config.hasAttributeNS(null, "reportPreviousSessionAuthnMethod")) {
            builder.addPropertyValue("reportPreviousSessionAuthnMethod", XMLHelper.getAttributeValueAsBoolean(config
                    .getAttributeNodeNS(null, "reportPreviousSessionAuthnMethod")));
        } else {
            builder.addPropertyValue("reportPreviousSessionAuthnMethod", false);
        }
    }
}