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

import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.config.SpringConfigurationUtils;

/**
 * Spring bean definition parser for profile handler root element.
 */
public class ProfileHandlerGroupBeanDefinitionParser extends AbstractBeanDefinitionParser {
    
    /** Class logger. */
    private static Logger log = Logger.getLogger(ProfileHandlerGroupBeanDefinitionParser.class);

    /** Schema type name. */
    public static final QName SCHEMA_TYPE = new QName(ProfileHandlerNamespaceHandler.NAMESPACE, "ProfileHandlerGroup");

    /** {@inheritDoc} */
    protected AbstractBeanDefinition parseInternal(Element config, ParserContext context) {
        BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(ProfileHandlerGroup.class);

        Map<QName, List<Element>> configChildren = XMLHelper.getChildElements(config);
        List<Element> children;

        children = configChildren.get(new QName(ProfileHandlerNamespaceHandler.NAMESPACE, "ErrorHandler"));
        if(log.isDebugEnabled()){
            log.debug(children.size() + " error handler definitions found");
        }
        builder.addPropertyValue("errorHandler", SpringConfigurationUtils.parseCustomElement(children.get(0), context));

        children = configChildren.get(new QName(ProfileHandlerNamespaceHandler.NAMESPACE, "ProfileHandler"));
        if(log.isDebugEnabled()){
            log.debug(children.size() + " profile handler definitions found");
        }
        builder.addPropertyValue("profileHandlers", SpringConfigurationUtils.parseCustomElements(children, context));

        children = configChildren.get(new QName(ProfileHandlerNamespaceHandler.NAMESPACE, "AuthenticationHandler"));
        if(log.isDebugEnabled()){
            log.debug(children.size() + " authentication handler definitions found");
        }
        builder.addPropertyValue("authenticationHandlers", SpringConfigurationUtils.parseCustomElements(children,
                context));

        return builder.getBeanDefinition();
    }

    /** {@inheritDoc} */
    protected boolean shouldGenerateId() {
        return true;
    }
}