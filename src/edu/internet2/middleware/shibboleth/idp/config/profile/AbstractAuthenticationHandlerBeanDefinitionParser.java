/*
 * Copyright [2007] [University Corporation for Advanced Internet Development, Inc.]
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

package edu.internet2.middleware.shibboleth.idp.config.profile;

import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.w3c.dom.Element;

/**
 * Base class for authentication handler definition parsers.
 */
public abstract class AbstractAuthenticationHandlerBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

    /** Class logger. */
    private static Logger log = Logger.getLogger(AbstractAuthenticationHandlerBeanDefinitionParser.class);

    /** {@inheritDoc} */
    protected void doParse(Element config, BeanDefinitionBuilder builder) {

        int duration = Integer.parseInt(config.getAttributeNS(null, "authenticationDuration"));
        if (log.isDebugEnabled()) {
            log.debug("Authentication handler declared duration of " + duration + " minutes");
        }
        builder.addPropertyValue("authenticationDuration", duration);

        String authnMethod;
        ArrayList<String> authnMethods = new ArrayList<String>();
        List<Element> authnMethodElems = XMLHelper.getChildElementsByTagNameNS(config,
                ProfileHandlerNamespaceHandler.NAMESPACE, "AuthenticationMethod");
        for (Element authnMethodElem : authnMethodElems) {
            authnMethod = DatatypeHelper.safeTrimOrNullString(authnMethodElem.getTextContent());
            if (log.isDebugEnabled()) {
                log.debug("Authentication handler declared support for authentication method " + authnMethod);
            }
            authnMethods.add(authnMethod);
        }
        builder.addPropertyValue("authenticationMethods", authnMethods);
    }

    /** {@inheritDoc} */
    protected boolean shouldGenerateId() {
        return true;
    }
}