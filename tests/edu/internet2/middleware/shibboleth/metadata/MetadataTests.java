/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.] Licensed under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in
 * writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.metadata;

import java.io.File;
import java.util.Iterator;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.opensaml.common.SAMLObjectTestCaseConfigInitializer;
import org.opensaml.common.xml.ParserPoolManager;
import org.opensaml.saml2.metadata.AttributeAuthorityDescriptor;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataCache;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.impl.CachingMetadataProvider;
import org.opensaml.saml2.metadata.provider.impl.SoftReferenceMetadataCache;
import org.opensaml.saml2.metadata.resolver.impl.URLResolver;
import org.opensaml.xml.Configuration;
import org.w3c.dom.Document;

import edu.internet2.middleware.shibboleth.xml.Parser;

/**
 * Validation suite for the SAML Metadata engine.
 * 
 * @author Walter Hoehn
 */

public class MetadataTests extends TestCase {

	// TODO add back test for "inline" metadata
	// TODO query for extension/shib-proprietary metadata

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

		// TODO delete this stuff when the library can do default initialization

		Class clazz = SAMLObjectTestCaseConfigInitializer.class;
		ParserPoolManager ppMgr = ParserPoolManager.getInstance();

		// Common Object Provider Configuration
		Document commonConfig = ppMgr.parse(clazz.getResourceAsStream("/common-config.xml"));
		Configuration.load(commonConfig);

		// SAML 1.X Assertion Object Provider Configuration
		Document saml1AssertionConfig = ppMgr.parse(clazz.getResourceAsStream("/saml1-assertion-config.xml"));
		Configuration.load(saml1AssertionConfig);

		// SAML 1.X Protocol Object Provider Configuration
		Document saml1ProtocolConfig = ppMgr.parse(clazz.getResourceAsStream("/saml1-protocol-config.xml"));
		Configuration.load(saml1ProtocolConfig);

		// SAML 2.0 Metadata Object Provider Configuration
		Document saml2mdConfig = ppMgr.parse(clazz.getResourceAsStream("/saml2-metadata-config.xml"));
		Configuration.load(saml2mdConfig);

		// SAML 2.0 Assertion Object Provider Configuration
		Document saml2assertionConfig = ppMgr.parse(clazz.getResourceAsStream("/saml2-assertion-config.xml"));
		Configuration.load(saml2assertionConfig);

		// SAML 2.0 Protocol Object Provider Configuration
		Document saml2protocolConfig = ppMgr.parse(clazz.getResourceAsStream("/saml2-protocol-config.xml"));
		Configuration.load(saml2protocolConfig);

	}

	public void testBasicSAMLXML() {

		try {
			// Load metadata
			MetadataCache cache = new SoftReferenceMetadataCache(60L, (short) 5, 60L);
			cache
					.addMetadataResolver(new URLResolver("foobar", new File("src/conf/IQ-metadata.xml").toURL()
							.toString()));
			MetadataProvider metadata = new CachingMetadataProvider(cache);

			// Basic Query
			EntityDescriptor entity = metadata.getEntityDescriptor("urn:mace:inqueue:example.edu");
			assertNotNull("Unable to find test provider", entity);

			// Check the parent descriptor
			assertNotNull("Entity parent access is broken: no parent", entity.getParent());
			assertTrue("Entity parent access is broken: wrong parent type.",
					entity.getParent() instanceof EntitiesDescriptor);
			assertEquals("Descriptor group is wrong.", ((EntitiesDescriptor) entity.getParent()).getName(),
					"urn:mace:inqueue");

			// Check descriptor roles
			IDPSSODescriptor idp = entity.getIDPSSODescriptor().get(0);
			AttributeAuthorityDescriptor aa = entity.getAttributeAuthorityDescriptor().get(0);
			SPSSODescriptor sp = entity.getSPSSODescriptor().get(0);
			assertNotNull("Missing IdP provider role.", idp);
			assertNotNull("Missing AA provider role.", aa);
			assertNotNull("Missing SP provider role.", sp);

			// SP-specific checks
			assertEquals("Incorrect assertion consumer service location.", sp.getAssertionConsumerServices().get(0)
					.getLocation(), "https://wayf.internet2.edu/Shibboleth.sso/SAML/POST");

		} catch (Exception e) {
			e.printStackTrace();
			fail("Failed to correctly load metadata: " + e);
		}
	}

	public void testKeyDescriptorLookup() {

		try {
			// Load metadata
			MetadataCache cache = new SoftReferenceMetadataCache(60L, (short) 5, 60L);
			cache
					.addMetadataResolver(new URLResolver("foobar", new File("src/conf/IQ-metadata.xml").toURL()
							.toString()));
			MetadataProvider metadata = new CachingMetadataProvider(cache);

			// Grab the Key Descriptors for an entity descriptor
			Iterator<KeyDescriptor> keys = metadata.getEntityDescriptor("urn:mace:inqueue:example.edu")
					.getSPSSODescriptor().get(0).getKeyDescriptors().iterator();

			// Make sure we have the expected key name
			KeyDescriptor key = keys.next();
			assertNotNull("No key descriptors found.", key);
			assertTrue("Encountered an unexpected number of key names", (key.getKeyInfo().getKeyNames().size() == 1));
			assertEquals("Encountered unexpected key names", "wayf.internet2.edu", key.getKeyInfo().getKeyNames()
					.get(0));

		} catch (Exception e) {
			fail("Failed to correctly load metadata: " + e);
		}
	}
}
