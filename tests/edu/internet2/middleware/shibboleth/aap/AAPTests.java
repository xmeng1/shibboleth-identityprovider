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

package edu.internet2.middleware.shibboleth.aap;

import java.io.File;
import java.io.FileInputStream;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLException;
import org.opensaml.XML;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aap.provider.XMLAAP;
import edu.internet2.middleware.shibboleth.metadata.Metadata;
import edu.internet2.middleware.shibboleth.metadata.provider.XMLMetadata;

/**
 * Validation suite for the <code>Metadata</code> interface.
 * 
 * @author Walter Hoehn
 */

public class AAPTests extends TestCase {

	public AAPTests(String name) {

		super(name);
		BasicConfigurator.resetConfiguration();
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	public static void main(String[] args) {

		junit.textui.TestRunner.run(AAPTests.class);
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	protected void setUp() throws Exception {

		super.setUp();
	}

	public void testBasic() {

		try {
			AAP aap = new XMLAAP(new File("src/conf/AAP.xml").toURL().toString());

			assertFalse("anyAttribute was true", aap.anyAttribute());

			AttributeRule rule = aap.lookup("affiliation");
			assertNotNull("Unable to find rule", rule);
			assertTrue("Rule wasn't scoped", rule.getScoped());
			assertFalse("Rule was case-sensitive", rule.getCaseSensitive());

			SAMLAttribute a1 = new SAMLAttribute(new FileInputStream("data/attribute1.xml"));
			SAMLAttribute a2 = new SAMLAttribute((Element) a1.toDOM().cloneNode(true));

			rule = aap.lookup(a1.getName(), a1.getNamespace());
			assertNotNull("Unable to find rule", rule);

			rule.apply(a1, null);
			try {
				a1.checkValidity();
				assertTrue("Attribute should have been stripped clean", false);
			} catch (SAMLException ex) {}

			Metadata metadata = new XMLMetadata(new File("src/conf/IQ-sites.xml").toURL().toString());
			rule.apply(a2, metadata.lookup("urn:mace:inqueue:example.edu").getAttributeAuthorityDescriptor(
					XML.SAML11_PROTOCOL_ENUM));
			a2.checkValidity();
			assertTrue("Value was unexpected", "member".equalsIgnoreCase((String) a2.getValues().next()));

		} catch (Exception e) {
			fail("Failed to correctly load AAP: " + e);
		}
	}
}
