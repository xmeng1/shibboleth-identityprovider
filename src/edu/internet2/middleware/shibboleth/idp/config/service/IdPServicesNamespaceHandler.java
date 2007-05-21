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

import edu.internet2.middleware.shibboleth.common.config.BaseSpringNamespaceHandler;

/**
 * Spring namespace handler for IdP service definitions.
 */
public class IdPServicesNamespaceHandler extends BaseSpringNamespaceHandler {

    /** IdP services namespace URI. */
    public static final String NAMESPACE = "urn:mace:shibboleth:2.0:idp:services";

    /** {@inheritDoc} */
    public void init() {
        IdPConfigBeanDefinitionParser parser = new IdPConfigBeanDefinitionParser();
        registerBeanDefinitionParser(IdPConfigBeanDefinitionParser.ELEMENT_NAME, parser);
        registerBeanDefinitionParser(IdPConfigBeanDefinitionParser.SCHEMA_TYPE, parser);

        registerBeanDefinitionParser(IdPLoggingServiceBeanDefinitionParser.ELEMENT_NAME,
                new IdPLoggingServiceBeanDefinitionParser());
    }
}