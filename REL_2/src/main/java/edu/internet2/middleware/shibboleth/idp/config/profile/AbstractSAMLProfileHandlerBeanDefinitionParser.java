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

import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.config.profile.AbstractShibbolethProfileHandlerBeanDefinitionParser;

/**
 * Base class for SAML profile handler configuration parsers.
 */
public abstract class AbstractSAMLProfileHandlerBeanDefinitionParser extends
        AbstractShibbolethProfileHandlerBeanDefinitionParser {

    /** {@inheritDoc} */
    protected void doParse(Element config, BeanDefinitionBuilder builder) {
        super.doParse(config, builder);

        builder.addPropertyReference("idGenerator", config.getAttributeNS(null, "idGeneratorId"));

        builder.addPropertyReference("messageDecoders", "shibboleth.MessageDecoders");

        builder.addPropertyReference("messageEncoders", "shibboleth.MessageEncoders");

        builder.addPropertyValue("inboundBinding", DatatypeHelper.safeTrimOrNullString(config.getAttributeNS(null,
                "inboundBinding")));

        builder.addPropertyValue("supportedOutboundBindings", XMLHelper.getAttributeValueAsList(config
                .getAttributeNodeNS(null, "outboundBindingEnumeration")));
    }
}