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

import java.util.ArrayList;
import java.util.List;

import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.config.SpringConfigurationUtils;
import edu.internet2.middleware.shibboleth.idp.config.profile.ProfileHandlerNamespaceHandler;

/**
 * Base class for authentication handler definition parsers.
 */
public abstract class AbstractLoginHandlerBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

    /** Class logger. */
    private static Logger log = LoggerFactory.getLogger(AbstractLoginHandlerBeanDefinitionParser.class);

    /** {@inheritDoc} */
    protected void doParse(Element config, BeanDefinitionBuilder builder) {
        log.debug("Parsing configuration for {} authentication handler.", XMLHelper.getXSIType(config).getLocalPart());

        long duration = 30 * 60 * 1000;
        if (config.hasAttributeNS(null, "authenticationDuration")) {
            duration = SpringConfigurationUtils.parseDurationToMillis("'authenticationDuration' on LoginHandler of type "
                    + XMLHelper.getXSIType(config), config.getAttributeNS(null, "authenticationDuration"), 1000 * 60);
        }
        log.debug("Authentication duration: {}ms", duration);
        builder.addPropertyValue("authenticationDuration", duration);

        String authnMethod;
        ArrayList<String> authnMethods = new ArrayList<String>();
        List<Element> authnMethodElems = XMLHelper.getChildElementsByTagNameNS(config,
                ProfileHandlerNamespaceHandler.NAMESPACE, "AuthenticationMethod");
        for (Element authnMethodElem : authnMethodElems) {
            authnMethod = DatatypeHelper.safeTrimOrNullString(authnMethodElem.getTextContent());
            log.debug("Authentication handler declared support for authentication method {}", authnMethod);
            authnMethods.add(authnMethod);
        }
        builder.addPropertyValue("authenticationMethods", authnMethods);
    }

    /** {@inheritDoc} */
    protected boolean shouldGenerateId() {
        return true;
    }
}