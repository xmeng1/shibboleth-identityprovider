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

import edu.internet2.middleware.shibboleth.common.config.BaseSpringNamespaceHandler;
import edu.internet2.middleware.shibboleth.common.config.profile.JSPErrorHandlerBeanDefinitionParser;
import edu.internet2.middleware.shibboleth.common.config.profile.VelocityErrorHandlerBeanDefinitionParser;
import edu.internet2.middleware.shibboleth.idp.config.profile.authn.RemoteUserLoginHandlerBeanDefinitionParser;
import edu.internet2.middleware.shibboleth.idp.config.profile.authn.UsernamePasswordLoginHandlerBeanDefinitionParser;
import edu.internet2.middleware.shibboleth.idp.config.profile.saml1.SAML1AttributeQueryProfileHandlerBeanDefinitionParser;
import edu.internet2.middleware.shibboleth.idp.config.profile.saml1.ShibbolethSSOProfileHandlerBeanDefinitionParser;
import edu.internet2.middleware.shibboleth.idp.config.profile.saml2.SAML2AttributeQueryProfileHandlerBeanDefinitionParser;
import edu.internet2.middleware.shibboleth.idp.config.profile.saml2.SAML2SSOProfileHandlerBeanDefinitionParser;

/**
 * Spring namespace handler for profile handler configurations.
 */
public class ProfileHandlerNamespaceHandler extends BaseSpringNamespaceHandler {

    /** Namespace URI. */
    public static final String NAMESPACE = "urn:mace:shibboleth:2.0:idp:profile-handler";

    /** {@inheritDoc} */
    public void init() {
        registerBeanDefinitionParser(IdPProfileHandlerManagerBeanDefinitionParser.SCHEMA_TYPE,
                new IdPProfileHandlerManagerBeanDefinitionParser());

        registerBeanDefinitionParser(ProfileHandlerGroupBeanDefinitionParser.SCHEMA_TYPE,
                new ProfileHandlerGroupBeanDefinitionParser());

        registerBeanDefinitionParser(new QName(NAMESPACE, JSPErrorHandlerBeanDefinitionParser.ELEMENT_NAME),
                new JSPErrorHandlerBeanDefinitionParser());

        registerBeanDefinitionParser(new QName(NAMESPACE, VelocityErrorHandlerBeanDefinitionParser.ELEMENT_NAME),
                new VelocityErrorHandlerBeanDefinitionParser());

        registerBeanDefinitionParser(ShibbolethSSOProfileHandlerBeanDefinitionParser.SCHEMA_TYPE,
                new ShibbolethSSOProfileHandlerBeanDefinitionParser());

        registerBeanDefinitionParser(SAML1AttributeQueryProfileHandlerBeanDefinitionParser.SCHEMA_TYPE,
                new SAML1AttributeQueryProfileHandlerBeanDefinitionParser());

        registerBeanDefinitionParser(StatusHandlerBeanDefinitionParser.SCHEMA_TYPE,
                new StatusHandlerBeanDefinitionParser());

        registerBeanDefinitionParser(SAML2AttributeQueryProfileHandlerBeanDefinitionParser.SCHEMA_TYPE,
                new SAML2AttributeQueryProfileHandlerBeanDefinitionParser());

        registerBeanDefinitionParser(SAML2SSOProfileHandlerBeanDefinitionParser.SCHEMA_TYPE,
                new SAML2SSOProfileHandlerBeanDefinitionParser());

        registerBeanDefinitionParser(RemoteUserLoginHandlerBeanDefinitionParser.SCHEMA_TYPE,
                new RemoteUserLoginHandlerBeanDefinitionParser());

        registerBeanDefinitionParser(UsernamePasswordLoginHandlerBeanDefinitionParser.SCHEMA_TYPE,
                new UsernamePasswordLoginHandlerBeanDefinitionParser());
    }
}