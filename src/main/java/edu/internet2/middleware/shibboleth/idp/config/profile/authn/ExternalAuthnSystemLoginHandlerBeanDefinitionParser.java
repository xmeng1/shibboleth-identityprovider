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

package edu.internet2.middleware.shibboleth.idp.config.profile.authn;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;

import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.idp.config.profile.ProfileHandlerNamespaceHandler;

/**
 * Spring bean definition parser for remote user authentication handlers.
 */
public class ExternalAuthnSystemLoginHandlerBeanDefinitionParser extends AbstractLoginHandlerBeanDefinitionParser {

    /** Schema type. */
    public static final QName SCHEMA_TYPE = new QName(ProfileHandlerNamespaceHandler.NAMESPACE, "ExternalAuthn");

    /** {@inheritDoc} */
    protected Class getBeanClass(Element arg0) {
        return ExternalAuthnSystemLoginHandlerFactoryBean.class;
    }

    /** {@inheritDoc} */
    protected void doParse(Element config, BeanDefinitionBuilder builder) {
        super.doParse(config, builder);

        if (config.hasAttributeNS(null, "protectedServletPath")) {
            builder.addPropertyValue("protectedServletPath",
                    DatatypeHelper.safeTrimOrNullString(config.getAttributeNS(null, "protectedServletPath")));
        } else {
            builder.addPropertyValue("protectedServletPath", "/Authn/External");
        }

        List<Element> queryParamElements = XMLHelper.getChildElementsByTagNameNS(config,
                ProfileHandlerNamespaceHandler.NAMESPACE, "QueryParam");
        builder.addPropertyValue("queryParams", parseQueryParameters(queryParamElements));
    }

    /**
     * Parses the query parameter elements, if any, in to a map.
     * 
     * @param queryParamElements query parameter elements, may be null or empty
     * 
     * @return the map of query elements indexed by the parameter name
     */
    protected Map<String, String> parseQueryParameters(List<Element> queryParamElements) {
        if (queryParamElements == null || queryParamElements.isEmpty()) {
            return Collections.emptyMap();
        }

        HashMap<String, String> params = new HashMap<String, String>();

        String paramName;
        String paramValue;
        for (Element queryParamElement : queryParamElements) {
            paramName = DatatypeHelper.safeTrimOrNullString(queryParamElement.getAttributeNS(null, "name"));
            if (paramName == null) {
                throw new BeanCreationException("Query parameter name may not be null or empty");
            }
            paramValue = DatatypeHelper.safeTrimOrNullString(queryParamElement.getAttributeNS(null, "value"));
            if (paramValue == null) {
                throw new BeanCreationException("Query parameter value may not be null or empty");
            }
            params.put(paramName, paramValue);
        }

        return params;
    }
}