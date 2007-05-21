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

package edu.internet2.middleware.shibboleth.idp.config.service;

import javax.xml.namespace.QName;

import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.w3c.dom.Element;

/**
 * Spring bean definition parser for the IdP logging service.
 */
public class IdPLoggingServiceBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

    /** Element name. */
    public static final QName ELEMENT_NAME = new QName(IdPServicesNamespaceHandler.NAMESPACE, "LoggingConfiguration");

    /** {@inheritDoc} */
    protected Class getBeanClass(Element arg0) {
        return IdPLoggingService.class;
    }

    /** {@inheritDoc} */
    protected void doParse(Element config, BeanDefinitionBuilder builder) {
        builder.addConstructorArgReference(config.getAttributeNS(null, "timerId"));
        builder.addConstructorArg(config.getTextContent());
        builder.setInitMethodName("initialize");
    }
    
    /** {@inheritDoc} */
    protected boolean shouldGenerateId() {
        return true;
    }
}