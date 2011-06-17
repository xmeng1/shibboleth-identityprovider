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

package edu.internet2.middleware.shibboleth.idp;

import java.util.ArrayList;
import java.util.List;

import org.custommonkey.xmlunit.XMLTestCase;
import org.custommonkey.xmlunit.XMLUnit;
import org.opensaml.Configuration;
import org.opensaml.util.resource.ClasspathResource;
import org.opensaml.util.resource.Resource;
import org.opensaml.util.resource.ResourceException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.GenericApplicationContext;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.config.SpringConfigurationUtils;

/**
 * Base unit test case for Spring configuration tests.
 */
public abstract class TestCaseBase extends XMLTestCase {

    /** Parser manager used to parse XML. */
    protected static BasicParserPool parser;

    /** Factory for XMLObject builders. */
    protected XMLObjectBuilderFactory builderFactory;

    /** Factory for XMLObject marshallers. */
    protected MarshallerFactory marshallerFactory;

    /** Factory for XMLObject unmarshallers. */
    protected UnmarshallerFactory unmarshallerFactory;

    /** Class logger. */
    private static Logger log = LoggerFactory.getLogger(TestCaseBase.class);

    /** Configuration resources to be loaded for all unit tests. */
    private List<Resource> configResources;

    /** {@inheritDoc} */
    protected void setUp() throws Exception {
        XMLUnit.setIgnoreWhitespace(true);

        try {
            ShibTestBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            fail(e.getMessage());
        }

        parser = new BasicParserPool();
        parser.setNamespaceAware(true);
        builderFactory = Configuration.getBuilderFactory();
        marshallerFactory = Configuration.getMarshallerFactory();
        unmarshallerFactory = Configuration.getUnmarshallerFactory();

        configResources = new ArrayList<Resource>();
    }

    /**
     * Creates a Spring application context from the instance defined config resources.
     * 
     * @return the created context
     * 
     * @throws ResourceException thrown if there is a problem reading the configuration resources
     */
    protected ApplicationContext createSpringContext() throws ResourceException {
        return createSpringContext(configResources);
    }

    /**
     * Creates a Spring application context from the given configuration and any instance registered configurations.
     * 
     * @param config spring configuration file to be located on the classpath
     * 
     * @return the configured spring context
     * 
     * @throws ResourceException thrown if the given resources can not be located
     */
    protected ApplicationContext createSpringContext(String config) throws ResourceException {
        String[] configs = new String[1];
        configs[0] = config;
        return createSpringContext(configs);
    }

    /**
     * Creates a Spring application context from the given configurations and any instance registered configurations.
     * 
     * @param configs spring configuration files to be located on the classpath
     * 
     * @return the configured spring context
     * 
     * @throws ResourceException thrown if the given resources can not be located
     */
    protected ApplicationContext createSpringContext(String[] configs) throws ResourceException {
        ArrayList<Resource> resources = new ArrayList<Resource>();
        resources.addAll(configResources);
        if (configs != null) {
            for (String config : configs) {
                resources.add(new ClasspathResource(config));
            }
        }

        return createSpringContext(resources);
    }

    /**
     * Creates a Spring context from the given resources.
     * 
     * @param configs context configuration resources
     * 
     * @return the created context
     * 
     * @throws ResourceException thrown if there is a problem reading the configuration resources
     */
    protected ApplicationContext createSpringContext(List<Resource> configs) throws ResourceException {
        GenericApplicationContext gContext = new GenericApplicationContext();
        SpringConfigurationUtils.populateRegistry(gContext, configs);
        gContext.refresh();
        return gContext;
    }

    /**
     * Asserts a given XMLObject is equal to an expected DOM. The XMLObject is marshalled and the resulting DOM object
     * is compared against the expected DOM object for equality.
     * 
     * @param expectedDOM the expected DOM
     * @param xmlObject the XMLObject to be marshalled and compared against the expected DOM
     */
    public void assertEquals(Document expectedDOM, XMLObject xmlObject) {
        assertEquals("Marshalled DOM was not the same as the expected DOM", expectedDOM, xmlObject);
    }

    /**
     * Asserts a given XMLObject is equal to an expected DOM. The XMLObject is marshalled and the resulting DOM object
     * is compared against the expected DOM object for equality.
     * 
     * @param failMessage the message to display if the DOMs are not equal
     * @param expectedDOM the expected DOM
     * @param xmlObject the XMLObject to be marshalled and compared against the expected DOM
     */
    public void assertEquals(String failMessage, Document expectedDOM, XMLObject xmlObject) {
        Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
        if (marshaller == null) {
            fail("Unable to locate marshaller for " + xmlObject.getElementQName()
                    + " can not perform equality check assertion");
        }

        try {
            Element generatedDOM = marshaller.marshall(xmlObject, parser.newDocument());
            if (log.isDebugEnabled()) {
                log.debug("Marshalled DOM was " + XMLHelper.nodeToString(generatedDOM));
            }
            assertXMLEqual(failMessage, expectedDOM, generatedDOM.getOwnerDocument());
        } catch (Exception e) {
            log.error("Marshalling failed with the following error:", e);
            fail("Marshalling failed with the following error: " + e);
        }
    }

    /**
     * Unmarshalls an element file into its SAMLObject.
     * 
     * @param elementFile the classpath path to an XML document to unmarshall
     * 
     * @return the SAMLObject from the file
     */
    protected XMLObject unmarshallElement(String elementFile) {
        try {
            Document doc = parser.parse(TestCaseBase.class.getResourceAsStream(elementFile));
            Element samlElement = doc.getDocumentElement();

            Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(samlElement);
            if (unmarshaller == null) {
                fail("Unable to retrieve unmarshaller by DOM Element");
            }

            return unmarshaller.unmarshall(samlElement);
        } catch (XMLParserException e) {
            fail("Unable to parse element file " + elementFile);
        } catch (UnmarshallingException e) {
            fail("Unmarshalling failed when parsing element file " + elementFile + ": " + e);
        }

        return null;
    }
}