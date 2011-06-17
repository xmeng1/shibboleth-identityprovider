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

package edu.internet2.middleware.shibboleth.idp.config.profile.authn;

import java.util.List;

import javax.xml.namespace.QName;

import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.LazyList;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.idp.config.profile.ProfileHandlerNamespaceHandler;
import edu.internet2.middleware.shibboleth.idp.util.IPRange;

/** Spring bean definition parser for IP address authentication handlers. */
public class IPAddressLoginHandlerBeanDefinitionParser extends AbstractLoginHandlerBeanDefinitionParser {

    /** Schema type. */
    public static final QName SCHEMA_TYPE = new QName(ProfileHandlerNamespaceHandler.NAMESPACE, "IPAddress");

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(IPAddressLoginHandlerBeanDefinitionParser.class);

    /** {@inheritDoc} */
    protected Class getBeanClass(Element element) {
        return IPAddressLoginHandlerFactoryBean.class;
    }

    /** {@inheritDoc} */
    protected void doParse(Element config, BeanDefinitionBuilder builder) {
        super.doParse(config, builder);

        String username = DatatypeHelper.safeTrimOrNullString(config.getAttributeNS(null, "username"));
        if (username == null) {
            String msg = "No username specified.";
            log.error(msg);
            throw new BeanCreationException(msg);
        }
        log.debug("authenticated username: {}", username);
        builder.addPropertyValue("authenticatedUser", username);

        List<IPRange> ranges = getIPRanges(config);
        log.debug("registered IP ranges: {}", ranges.size());
        builder.addPropertyValue("ipRanges", ranges);

        boolean defaultDeny = XMLHelper.getAttributeValueAsBoolean(config.getAttributeNodeNS(null, "defaultDeny"));
        log.debug("default deny: {}", defaultDeny);
        builder.addPropertyValue("ipInRangeIsAuthenticated", defaultDeny);
    }

    /**
     * Gets the list of IP ranges given in the configuration.
     * 
     * @param config current configuration
     * 
     * @return list of IP ranges
     */
    protected List<IPRange> getIPRanges(Element config) {
        List<Element> ipEntries = XMLHelper.getChildElementsByTagNameNS(config,
                ProfileHandlerNamespaceHandler.NAMESPACE, "IPEntry");
        if (ipEntries == null || ipEntries.isEmpty()) {
            String msg = "At least one IPEntry must be specified.";
            log.error(msg);
            throw new BeanCreationException(msg);
        }

        List<IPRange> ranges = new LazyList<IPRange>();
        for (Element ipEntry : ipEntries) {
            ranges.add(IPRange.parseCIDRBlock(ipEntry.getTextContent()));
        }

        return ranges;
    }
}