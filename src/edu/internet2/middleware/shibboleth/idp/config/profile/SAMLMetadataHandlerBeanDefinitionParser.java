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

import javax.xml.namespace.QName;

import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.config.profile.AbstractRequestURIMappedProfileHandlerBeanDefinitionParser;
import edu.internet2.middleware.shibboleth.idp.profile.SAMLMetadataProfileHandler;

/**
 * Spring bean definition parser for {@link SAMLMetadataProfileHandler}s.
 */
public class SAMLMetadataHandlerBeanDefinitionParser extends AbstractRequestURIMappedProfileHandlerBeanDefinitionParser {

    /** Schema type. */
    public static final QName SCHEMA_TYPE = new QName(ProfileHandlerNamespaceHandler.NAMESPACE, "SAMLMetadata");

    /** {@inheritDoc} */
    protected Class getBeanClass(Element arg0) {
        return SAMLMetadataProfileHandler.class;
    }

    /** {@inheritDoc} */
    protected void doParse(Element config, BeanDefinitionBuilder builder) {
        builder.addConstructorArg(config.getAttributeNS(null, "metadataFile"));
    }

    /** {@inheritDoc} */
    protected boolean shouldGenerateId() {
        return true;
    }
}