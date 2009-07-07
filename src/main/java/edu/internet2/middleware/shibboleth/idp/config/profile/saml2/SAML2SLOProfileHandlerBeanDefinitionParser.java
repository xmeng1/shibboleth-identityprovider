/*
 *  Copyright 2009 NIIF Institute.
 * 
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *  under the License.
 */
package edu.internet2.middleware.shibboleth.idp.config.profile.saml2;

import edu.internet2.middleware.shibboleth.idp.config.profile.ProfileHandlerNamespaceHandler;
import edu.internet2.middleware.shibboleth.idp.profile.saml2.SLOProfileHandler;
import javax.xml.namespace.QName;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.w3c.dom.Element;

/**
 *
 */
public class SAML2SLOProfileHandlerBeanDefinitionParser extends AbstractSAML2ProfileHandlerBeanDefinitionParser {

    /** Schema type. */
    public static final QName SCHEMA_TYPE =
            new QName(ProfileHandlerNamespaceHandler.NAMESPACE, "SAML2SLO");

    /** {@inheritDoc} */
    @Override
    protected Class getBeanClass(Element arg0) {
        return SLOProfileHandler.class;
    }

    @Override
    protected void doParse(Element config, BeanDefinitionBuilder builder) {
        super.doParse(config, builder);
    }
}
