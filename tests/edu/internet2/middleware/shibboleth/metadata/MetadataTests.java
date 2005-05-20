/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
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

package edu.internet2.middleware.shibboleth.metadata;

import java.io.File;
import java.io.FileInputStream;
import java.util.Arrays;
import java.util.Iterator;

import javax.xml.parsers.DocumentBuilderFactory;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.opensaml.XML;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import edu.internet2.middleware.shibboleth.common.Constants;
import edu.internet2.middleware.shibboleth.idp.IdPConfig;
import edu.internet2.middleware.shibboleth.metadata.provider.XMLMetadata;
import edu.internet2.middleware.shibboleth.xml.Parser;

/**
 * Validation suite for the <code>Metadata</code> interface.
 * 
 * @author Walter Hoehn
 */

public class MetadataTests extends TestCase {

	private Parser.DOMParser parser = new Parser.DOMParser(true);

	public MetadataTests(String name) {

		super(name);
		BasicConfigurator.resetConfiguration();
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	public static void main(String[] args) {

		junit.textui.TestRunner.run(MetadataTests.class);
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	protected void setUp() throws Exception {

		super.setUp();

	}

	public void testBasicShibbolethXML() {

		try {
			Metadata metadata = new XMLMetadata(new File("data/sites1.xml").toURL().toString());

			assertNotNull("Unable to find test provider", metadata.lookup("bahsite"));
			assertNotNull("Unable to find test provider", metadata.lookup("rootsite"));

			// This should probably be made more robust at some point
			assertNotNull("Incorrect provider role.", metadata.lookup("bahsite").getSPSSODescriptor(
					XML.SAML11_PROTOCOL_ENUM));

			assertEquals("Incorrect parsing of assertion consumer URL.", ((Endpoint) metadata.lookup("bahsite")
					.getSPSSODescriptor(XML.SAML11_PROTOCOL_ENUM).getAssertionConsumerServiceManager().getEndpoints()
					.next()).getLocation(), "http://foo.com/SHIRE");

			Iterator keys = metadata.lookup("rootsite").getSPSSODescriptor(XML.SAML11_PROTOCOL_ENUM)
					.getKeyDescriptors();
			KeyDescriptor key1 = (KeyDescriptor) keys.next();
			KeyDescriptor key2 = (KeyDescriptor) keys.next();
			assertTrue("Incorrect attribute requester key parsing.", key1 != null && key2 != null);

			String[] control = new String[]{
					"C=US, ST=Tennessee, L=Memphis, O=The University of Memphis, OU=Information Systems, CN=test2.memphis.edu",
					"C=US, ST=Tennessee, L=Memphis, O=The University of Memphis, OU=Information Systems, CN=test1.memphis.edu"};
			String[] meta = new String[]{key1.getKeyInfo().itemKeyName(0).getKeyName(),
					key2.getKeyInfo().itemKeyName(0).getKeyName()};
			Arrays.sort(meta);
			Arrays.sort(control);
			assertTrue("Encountered unexpected key names", Arrays.equals(control, meta));
		} catch (Exception e) {
			fail("Failed to correctly load metadata: " + e);
		}
	}

	public void testBasicSAMLXML() {

		try {
			Metadata metadata = new XMLMetadata(new File("src/conf/IQ-sites.xml").toURL().toString());

			EntityDescriptor entity = metadata.lookup("urn:mace:inqueue:example.edu");

			assertNotNull("Unable to find test provider", entity);
			assertEquals("Descriptor group is wrong.", entity.getEntitiesDescriptor().getName(), "urn:mace:inqueue");

			IDPSSODescriptor idp = entity.getIDPSSODescriptor(edu.internet2.middleware.shibboleth.common.XML.SHIB_NS);
			AttributeAuthorityDescriptor aa = entity.getAttributeAuthorityDescriptor(XML.SAML11_PROTOCOL_ENUM);
			SPSSODescriptor sp = entity.getSPSSODescriptor(XML.SAML11_PROTOCOL_ENUM);

			assertNotNull("Missing IdP provider role.", idp);
			assertNotNull("Missing AA provider role.", aa);
			assertNotNull("Missing SP provider role.", sp);

			assertEquals("Incorrect assertion consumer service location.", ((Endpoint) sp
					.getAssertionConsumerServiceManager().getEndpoints().next()).getLocation(),
					"https://wayf.internet2.edu/Shibboleth.shire");

			Iterator keys = sp.getKeyDescriptors();
			KeyDescriptor key = (KeyDescriptor) keys.next();
			assertNotNull("Incorrect attribute requester key parsing.", key);

			String[] control = new String[]{"wayf.internet2.edu"};
			String[] meta = new String[]{key.getKeyInfo().itemKeyName(0).getKeyName()};
			Arrays.sort(meta);
			Arrays.sort(control);
			assertTrue("Encountered unexpected key names", Arrays.equals(control, meta));
		} catch (Exception e) {
			fail("Failed to correctly load metadata: " + e);
		}
	}

	public void testInlineSAMLXML() {

		try {

			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			docFactory.setNamespaceAware(true);
			Document placeHolder = docFactory.newDocumentBuilder().newDocument();

			Element providerNode = placeHolder.createElementNS(IdPConfig.configNameSpace, "MetadataProvider");

			Document xmlConfig = parser.parse(new InputSource(new FileInputStream("src/conf/IQ-sites.xml")));
			Node metadataNode = placeHolder.importNode(xmlConfig.getDocumentElement(), true);
			providerNode.appendChild(metadataNode);

			Metadata metadata = new XMLMetadata(providerNode);

			EntityDescriptor entity = metadata.lookup("urn:mace:inqueue:example.edu");

			assertNotNull("Unable to find test provider", entity);
			assertEquals("Descriptor group is wrong.", entity.getEntitiesDescriptor().getName(), "urn:mace:inqueue");

			IDPSSODescriptor idp = entity.getIDPSSODescriptor(edu.internet2.middleware.shibboleth.common.XML.SHIB_NS);
			AttributeAuthorityDescriptor aa = entity.getAttributeAuthorityDescriptor(XML.SAML11_PROTOCOL_ENUM);
			SPSSODescriptor sp = entity.getSPSSODescriptor(XML.SAML11_PROTOCOL_ENUM);

			assertNotNull("Missing IdP provider role.", idp);
			assertNotNull("Missing AA provider role.", aa);
			assertNotNull("Missing SP provider role.", sp);

			assertEquals("Incorrect assertion consumer service location.", ((Endpoint) sp
					.getAssertionConsumerServiceManager().getEndpoints().next()).getLocation(),
					"https://wayf.internet2.edu/Shibboleth.shire");

			Iterator keys = sp.getKeyDescriptors();
			KeyDescriptor key = (KeyDescriptor) keys.next();
			assertNotNull("Incorrect attribute requester key parsing.", key);

			String[] control = new String[]{"wayf.internet2.edu"};
			String[] meta = new String[]{key.getKeyInfo().itemKeyName(0).getKeyName()};
			Arrays.sort(meta);
			Arrays.sort(control);
			assertTrue("Encountered unexpected key names", Arrays.equals(control, meta));
		} catch (Exception e) {
			fail("Failed to correctly load metadata: " + e);
		}
	}

	public void testExtensionSAMLXML() {

		try {
			Metadata metadata = new XMLMetadata(new File("data/metadata10.xml").toURL().toString());

			EntityDescriptor entity = metadata.lookup("urn-x:testSP1");
			assertNotNull("Unable to find test provider", entity);

			AttributeRequesterDescriptor ar = entity.getAttributeRequesterDescriptor(XML.SAML11_PROTOCOL_ENUM);
			assertNotNull("Missing AR provider role.", ar);

			Iterator formats = ar.getNameIDFormats();
			assertTrue("Encountered unexpected NameIDFormat", formats.hasNext()
					&& Constants.SHIB_NAMEID_FORMAT_URI.equals(formats.next()));
		} catch (Exception e) {
			fail("Failed to correctly load metadata: " + e);
		}
	}
}
