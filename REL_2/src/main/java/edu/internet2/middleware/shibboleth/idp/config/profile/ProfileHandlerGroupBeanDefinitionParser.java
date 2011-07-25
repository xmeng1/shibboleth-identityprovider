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

package edu.internet2.middleware.shibboleth.idp.config.profile;

import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;

import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.config.SpringConfigurationUtils;

/** Spring bean definition parser for profile handler root element. */
public class ProfileHandlerGroupBeanDefinitionParser implements BeanDefinitionParser {

    /** Schema type name. */
    public static final QName SCHEMA_TYPE = new QName(ProfileHandlerNamespaceHandler.NAMESPACE, "ProfileHandlerGroup");

    /** Class logger. */
    private static Logger log = LoggerFactory.getLogger(ProfileHandlerGroupBeanDefinitionParser.class);

    /** {@inheritDoc} */
    public BeanDefinition parse(Element config, ParserContext context) {
        Map<QName, List<Element>> configChildren = XMLHelper.getChildElements(config);
        List<Element> children;

        children = configChildren.get(new QName(ProfileHandlerNamespaceHandler.NAMESPACE, "ErrorHandler"));
        log.debug("{} error handler definitions found", children.size());
        SpringConfigurationUtils.parseInnerCustomElement(children.get(0), context);

        children = configChildren.get(new QName(ProfileHandlerNamespaceHandler.NAMESPACE, "ProfileHandler"));
        log.debug("{} profile handler definitions found", children.size());
        SpringConfigurationUtils.parseInnerCustomElements(children, context);

        children = configChildren.get(new QName(ProfileHandlerNamespaceHandler.NAMESPACE, "LoginHandler"));
        log.debug("{} login handler definitions found", children.size());
        SpringConfigurationUtils.parseInnerCustomElements(children, context);

        return null;
    }
}