/*
 * Copyright 2008 University Corporation for Advanced Internet Development, Inc.
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

package edu.internet2.middleware.shibboleth.idp.config.profile.authn;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;

import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.idp.config.profile.ProfileHandlerNamespaceHandler;

/**
 * Spring bean definition parser for IP address authentication handlers.
 */
public class IPAddressLoginHandlerBeanDefinitionParser extends AbstractLoginHandlerBeanDefinitionParser {

    /** Schema type. */
    public static final QName SCHEMA_TYPE = new QName(ProfileHandlerNamespaceHandler.NAMESPACE, "IPAddress");

    /** Name of ip entry elements. */
    public static final QName IP_ENTRY_ELEMENT_NAME = new QName(ProfileHandlerNamespaceHandler.NAMESPACE, "IPEntry");

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(IPAddressLoginHandlerBeanDefinitionParser.class);

    /** {@inheritDoc} */
    protected Class getBeanClass(Element element) {
        return IPAddressLoginHandlerFactoryBean.class;
    }

    /** {@inheritDoc} */
    protected void doParse(Element config, BeanDefinitionBuilder builder) {
        super.doParse(config, builder);

        boolean defaultDeny = XMLHelper.getAttributeValueAsBoolean(config.getAttributeNodeNS(null, "defaultDeny"));
        log.debug("Setting defaultDeny to: {}", defaultDeny);
        builder.addPropertyValue("defaultDeny", defaultDeny);

        String username = DatatypeHelper.safeTrim(config.getAttributeNS(null, "username"));
        log.debug("Setting username to: {}", username);
        builder.addPropertyValue("username", username);

        Map<QName, List<Element>> children = XMLHelper.getChildElements(config);
        List<Element> ipEntries = children.get(IP_ENTRY_ELEMENT_NAME);
        List<String> addresses = new ArrayList<String>();

        for (Element element : ipEntries) {
            String address = DatatypeHelper.safeTrimOrNullString(element.getTextContent());
            if (address != null) {
                log.debug("Adding IP Address: {}", address);
                addresses.add(address);
            }
        }
        builder.addPropertyValue("addresses", addresses);
    }
}
