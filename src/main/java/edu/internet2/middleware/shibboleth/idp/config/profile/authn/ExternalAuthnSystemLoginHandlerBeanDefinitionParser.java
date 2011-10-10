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

import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.idp.config.profile.ProfileHandlerNamespaceHandler;

/**
 * Spring bean definition parser for remote user authentication handlers.
 */
public class ExternalAuthnSystemLoginHandlerBeanDefinitionParser extends AbstractLoginHandlerBeanDefinitionParser {

    /** Schema type. */
    public static final QName SCHEMA_TYPE = new QName(ProfileHandlerNamespaceHandler.NAMESPACE, "ExternalAuthn");

    /** {@inheritDoc} */
    protected Class getBeanClass(Element arg0) {
        return ExternalAuthnSystemLoginHandlerFactoryBean.class;
    }

    /** {@inheritDoc} */
    protected void doParse(Element config, BeanDefinitionBuilder builder) {
        super.doParse(config, builder);
        
        builder.addPropertyValue("externalAuthnPath",
                DatatypeHelper.safeTrimOrNullString(config.getAttributeNS(null, "externalAuthnPath")));
        
        if (config.hasAttributeNS(null, "supportsForcedAuthentication")) {
            builder.addPropertyValue("supportsForcedAuthentication", XMLHelper.getAttributeValueAsBoolean(config
                    .getAttributeNodeNS(null, "supportsForcedAuthentication")));
        } else {
            builder.addPropertyValue("supportsForcedAuthentication", false);
        }
        
        if (config.hasAttributeNS(null, "supportsPassiveAuthentication")) {
            builder.addPropertyValue("supportsPassiveAuthentication", XMLHelper.getAttributeValueAsBoolean(config
                    .getAttributeNodeNS(null, "supportsPassiveAuthentication")));
        } else {
            builder.addPropertyValue("supportsPassiveAuthentication", false);
        }
    }
}