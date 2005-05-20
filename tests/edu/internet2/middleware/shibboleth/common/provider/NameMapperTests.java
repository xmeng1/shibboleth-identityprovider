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

package edu.internet2.middleware.shibboleth.common.provider;

import java.io.File;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.security.Principal;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.opensaml.SAMLNameIdentifier;
import org.xml.sax.InputSource;

import edu.internet2.middleware.shibboleth.common.Credential;
import edu.internet2.middleware.shibboleth.common.IdentityProvider;
import edu.internet2.middleware.shibboleth.common.InvalidNameIdentifierException;
import edu.internet2.middleware.shibboleth.common.LocalPrincipal;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMapping;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMappingException;
import edu.internet2.middleware.shibboleth.common.NameMapper;
import edu.internet2.middleware.shibboleth.common.ServiceProvider;
import edu.internet2.middleware.shibboleth.xml.Parser;

/**
 * Validation suite for the <code>NameMapper</code>.
 * 
 * @author Walter Hoehn(wassa@columbia.edu)
 */

public class NameMapperTests extends TestCase {

	private static Logger log = Logger.getLogger(NameMapperTests.class.getName());
	private Parser.DOMParser parser = new Parser.DOMParser(true);

	public NameMapperTests(String name) {

		super(name);
		BasicConfigurator.resetConfiguration();
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	public static void main(String[] args) {

		junit.textui.TestRunner.run(NameMapperTests.class);
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	protected void setUp() throws Exception {

		super.setUp();

	}

	public void testCryptoMapping() {

		try {

			NameMapper nameMapper = new NameMapper();

			File file = new File("data/handle.jks");

			String rawConfig = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
					+ "<NameMapping xmlns=\"urn:mace:shibboleth:namemapper:1.0\""
					+ "		xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
					+ "		xsi:schemaLocation=\"urn:mace:shibboleth:namemapper:1.0 namemapper.xsd\" "
					+ " 			id=\"cryptotest\" format=\"urn:mace:shibboleth:1.0:nameIdentifier\" "
					+ "			type=\"CryptoHandleGenerator\" handleTTL=\"1800\">" + "		<KeyStorePath>"
					+ file.toURL().toString() + "</KeyStorePath>" + "		<KeyStorePassword>shibhs</KeyStorePassword>"
					+ "		<KeyStoreKeyAlias>handlekey</KeyStoreKeyAlias>"
					+ "		<KeyStoreKeyPassword>shibhs</KeyStoreKeyPassword>" + "	</NameMapping>";

			parser.parse(new InputSource(new StringReader(rawConfig)));
			nameMapper.addNameMapping(parser.getDocument().getDocumentElement());

			SAMLNameIdentifier nameId = nameMapper.getNameIdentifier("cryptotest", new LocalPrincipal("testprincipal"),
					new BasicServiceProvider(), new BasicIdentityProvider("urn-x:testid"));

			Principal principal = nameMapper.getPrincipal(nameId, new BasicServiceProvider(),
					new BasicIdentityProvider("urn-x:testid"));
			assertEquals("Round-trip handle validation failed.", principal.getName(), "testprincipal");

		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (NameIdentifierMappingException e) {
			fail("Error exercising NameMaper: " + e.getMessage());
		} catch (Exception e) {
			fail("Error exercising NameMaper: " + e.getMessage());
		}

	}

	public void testCryptoMappingExpiration() {

		try {

			NameMapper nameMapper = new NameMapper();

			File file = new File("data/handle.jks");

			String rawConfig = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
					+ "<NameMapping xmlns=\"urn:mace:shibboleth:namemapper:1.0\""
					+ "		xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
					+ "		xsi:schemaLocation=\"urn:mace:shibboleth:namemapper:1.0 namemapper.xsd\" "
					+ " 			id=\"cryptotest\" format=\"urn:mace:shibboleth:1.0:nameIdentifier\" "
					+ "			type=\"CryptoHandleGenerator\" handleTTL=\"10\">" + "		<KeyStorePath>"
					+ file.toURL().toString() + "</KeyStorePath>" + "		<KeyStorePassword>shibhs</KeyStorePassword>"
					+ "		<KeyStoreKeyAlias>handlekey</KeyStoreKeyAlias>"
					+ "		<KeyStoreKeyPassword>shibhs</KeyStoreKeyPassword>" + "	</NameMapping>";

			parser.parse(new InputSource(new StringReader(rawConfig)));
			nameMapper.addNameMapping(parser.getDocument().getDocumentElement());

			SAMLNameIdentifier nameId = nameMapper.getNameIdentifier("cryptotest", new LocalPrincipal("testprincipal"),
					new BasicServiceProvider(), new BasicIdentityProvider("urn-x:testid"));

			log.debug("Waiting 11 seconds for the handle to expire.");
			Thread.sleep(11000);

			Principal principal = nameMapper.getPrincipal(nameId, new BasicServiceProvider(),
					new BasicIdentityProvider("urn-x:testid"));

			fail("Error: crypto handle should have expired but appears to work.");

		} catch (InvalidNameIdentifierException e) {
			log.debug("As was expected, the handle was not valid: " + e);
			// This is the exception we are supposed to get
		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (NameIdentifierMappingException e) {
			fail("Error exercising NameMaper: " + e.getMessage());
		} catch (Exception e) {
			fail("Error exercising NameMaper: " + e.getMessage());
		}

	}

	public void testCryptoMappingWithOverriddenAlgorithms() {

		try {

			NameMapper nameMapper = new NameMapper();

			File file = new File("data/handle.jks");

			String rawConfig = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
					+ "<NameMapping xmlns=\"urn:mace:shibboleth:namemapper:1.0\""
					+ "		xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
					+ "		xsi:schemaLocation=\"urn:mace:shibboleth:namemapper:1.0 namemapper.xsd\" "
					+ " 			id=\"cryptotest\" format=\"urn:mace:shibboleth:1.0:nameIdentifier\" "
					+ "			type=\"CryptoHandleGenerator\" handleTTL=\"1800\">" + "		<KeyStorePath>"
					+ file.toURL().toString() + "</KeyStorePath>" + "		<KeyStorePassword>shibhs</KeyStorePassword>"
					+ "		<KeyStoreKeyAlias>handlekey</KeyStoreKeyAlias>"
					+ "		<KeyStoreKeyPassword>shibhs</KeyStoreKeyPassword>"
					+ "		<Cipher>DESede/CBC/PKCS5Padding</Cipher>" + "		<MAC>HmacSHA1</MAC>"
					+ "		<KeyStoreType>JCEKS</KeyStoreType>" + "	</NameMapping>";

			parser.parse(new InputSource(new StringReader(rawConfig)));
			nameMapper.addNameMapping(parser.getDocument().getDocumentElement());

			SAMLNameIdentifier nameId = nameMapper.getNameIdentifier("cryptotest", new LocalPrincipal("testprincipal"),
					new BasicServiceProvider(), new BasicIdentityProvider("urn-x:testid"));

			Principal principal = nameMapper.getPrincipal(nameId, new BasicServiceProvider(),
					new BasicIdentityProvider("urn-x:testid"));
			assertEquals("Round-trip handle validation failed.", principal.getName(), "testprincipal");

		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (NameIdentifierMappingException e) {
			fail("Error exercising NameMaper: " + e.getMessage());
		} catch (Exception e) {
			fail("Error exercising NameMaper: " + e.getMessage());
		}

	}

	public void testCryptoMappingBadQualifier() {

		try {

			NameMapper nameMapper = new NameMapper();

			File file = new File("data/handle.jks");

			String rawConfig = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
					+ "<NameMapping xmlns=\"urn:mace:shibboleth:namemapper:1.0\""
					+ "		xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
					+ "		xsi:schemaLocation=\"urn:mace:shibboleth:namemapper:1.0 namemapper.xsd\" "
					+ " 			id=\"cryptotest\" format=\"urn:mace:shibboleth:1.0:nameIdentifier\" "
					+ "			type=\"CryptoHandleGenerator\" handleTTL=\"1800\">" + "		<KeyStorePath>"
					+ file.toURL().toString() + "</KeyStorePath>" + "		<KeyStorePassword>shibhs</KeyStorePassword>"
					+ "		<KeyStoreKeyAlias>handlekey</KeyStoreKeyAlias>"
					+ "		<KeyStoreKeyPassword>shibhs</KeyStoreKeyPassword>" + "	</NameMapping>";

			parser.parse(new InputSource(new StringReader(rawConfig)));
			nameMapper.addNameMapping(parser.getDocument().getDocumentElement());

			SAMLNameIdentifier nameId = nameMapper.getNameIdentifier("cryptotest", new LocalPrincipal("testprincipal"),
					new BasicServiceProvider(), new BasicIdentityProvider("urn-x:good"));

			Principal principal = nameMapper.getPrincipal(nameId, new BasicServiceProvider(),
					new BasicIdentityProvider("urn-x:bad"));

			fail("Expected failure for bad name qualifier.");

		} catch (NameIdentifierMappingException e) {
			// This exception should be generated by this test

		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());

		} catch (Exception e) {
			fail("Error exercising NameMaper: " + e.getMessage());
		}

	}

	public void testDefaultConfig() {

		try {

			NameMapper nameMapper = new NameMapper();

			SAMLNameIdentifier nameId = nameMapper.getNameIdentifier(null, new LocalPrincipal("testprincipal"),
					new BasicServiceProvider(), new BasicIdentityProvider("urn-x:testid"));

			Principal principal = nameMapper.getPrincipal(nameId, new BasicServiceProvider(),
					new BasicIdentityProvider("urn-x:testid"));

			assertEquals("Round-trip handle validation failed.", principal.getName(), "testprincipal");

		} catch (NameIdentifierMappingException e) {
			fail("Error exercising NameMaper: " + e.getMessage());
		} catch (Exception e) {
			fail("Error exercising NameMaper: " + e.getMessage());
		}
	}

	public void testDefaultingId() {

		try {

			NameMapper nameMapper = new NameMapper();

			File file = new File("data/handle.jks");

			String rawConfig = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
					+ "<NameMapping xmlns=\"urn:mace:shibboleth:namemapper:1.0\""
					+ "		xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
					+ "		xsi:schemaLocation=\"urn:mace:shibboleth:namemapper:1.0 namemapper.xsd\" "
					+ "			format=\"urn:mace:shibboleth:1.0:nameIdentifier\""
					+ "		type=\"CryptoHandleGenerator\" handleTTL=\"1800\">" + "		<KeyStorePath>"
					+ file.toURL().toString() + "</KeyStorePath>" + "		<KeyStorePassword>shibhs</KeyStorePassword>"
					+ "		<KeyStoreKeyAlias>handlekey</KeyStoreKeyAlias>"
					+ "		<KeyStoreKeyPassword>shibhs</KeyStoreKeyPassword>" + "	</NameMapping>";

			parser.parse(new InputSource(new StringReader(rawConfig)));
			nameMapper.addNameMapping(parser.getDocument().getDocumentElement());

			SAMLNameIdentifier nameId = nameMapper.getNameIdentifier(null, new LocalPrincipal("testprincipal"),
					new BasicServiceProvider(), new BasicIdentityProvider("urn-x:testid"));

			Principal principal = nameMapper.getPrincipal(nameId, new BasicServiceProvider(),
					new BasicIdentityProvider("urn-x:testid"));

			assertEquals("Round-trip handle validation failed.", principal.getName(), "testprincipal");

			NameIdentifierMapping nameMapping = nameMapper.getNameIdentifierMappingById(null);
			if (!(nameMapping instanceof CryptoShibHandle)) {
				fail("HSNameMapper defaulted to incorrect name mapping.");
			}

		} catch (NameIdentifierMappingException e) {
			fail("Error exercising NameMaper: " + e.getMessage());
		} catch (Exception e) {
			fail("Error exercising NameMaper: " + e.getMessage());
		}
	}

	public void testDefaultingAmbiguousId() {

		try {

			NameMapper nameMapper = new NameMapper();

			File file = new File("data/handle.jks");

			String rawConfig = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
					+ "<NameMapping xmlns=\"urn:mace:shibboleth:namemapper:1.0\""
					+ "		xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
					+ "		xsi:schemaLocation=\"urn:mace:shibboleth:namemapper:1.0 namemapper.xsd\" "
					+ "			format=\"urn:mace:shibboleth:1.0:nameIdentifier\""
					+ "		type=\"CryptoHandleGenerator\" handleTTL=\"1800\">" + "		<KeyStorePath>"
					+ file.toURL().toString() + "</KeyStorePath>" + "		<KeyStorePassword>shibhs</KeyStorePassword>"
					+ "		<KeyStoreKeyAlias>handlekey</KeyStoreKeyAlias>"
					+ "		<KeyStoreKeyPassword>shibhs</KeyStoreKeyPassword>" + "	</NameMapping>";

			parser.parse(new InputSource(new StringReader(rawConfig)));
			nameMapper.addNameMapping(parser.getDocument().getDocumentElement());

			String rawConfig2 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
					+ "<NameMapping xmlns=\"urn:mace:shibboleth:namemapper:1.0\""
					+ "		xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
					+ "		xsi:schemaLocation=\"urn:mace:shibboleth:namemapper:1.0 namemapper.xsd\" "
					+ "			format=\"urn-x:testNameIdentifier\"" + "		type=\"CryptoHandleGenerator\" handleTTL=\"1800\">"
					+ "		<KeyStorePath>" + file.toURL().toString() + "</KeyStorePath>"
					+ "		<KeyStorePassword>shibhs</KeyStorePassword>"
					+ "		<KeyStoreKeyAlias>handlekey</KeyStoreKeyAlias>"
					+ "		<KeyStoreKeyPassword>shibhs</KeyStoreKeyPassword>" + "	</NameMapping>";

			parser.parse(new InputSource(new StringReader(rawConfig2)));

			nameMapper.addNameMapping(parser.getDocument().getDocumentElement());

			nameMapper.getNameIdentifier(null, new LocalPrincipal("testprincipal"), new BasicServiceProvider(),
					new BasicIdentityProvider("urn-x:testid"));

			fail("HSNameMapper defaulted to incorrect name mapping.");

			// This is only a failure if we don't get this exception
		} catch (NameIdentifierMappingException e) {

		} catch (Exception e) {

			fail("Error exercising NameMaper: " + e.getMessage());
		}
	}

	public void testMemoryMapping() {

		try {

			NameMapper nameMapper = new NameMapper();

			String rawConfig = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
					+ "<NameMapping xmlns=\"urn:mace:shibboleth:namemapper:1.0\""
					+ "		xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
					+ "		xsi:schemaLocation=\"urn:mace:shibboleth:namemapper:1.0 namemapper.xsd\" "
					+ "			id=\"memorytest\" " + "		format=\"urn:mace:shibboleth:1.0:nameIdentifier\""
					+ "		type=\"SharedMemoryShibHandle\" handleTTL=\"1800\"/>";

			parser.parse(new InputSource(new StringReader(rawConfig)));
			nameMapper.addNameMapping(parser.getDocument().getDocumentElement());

			SAMLNameIdentifier nameId = nameMapper.getNameIdentifier("memorytest", new LocalPrincipal("testprincipal"),
					new BasicServiceProvider(), new BasicIdentityProvider("urn-x:testid"));

			Principal principal = nameMapper.getPrincipal(nameId, new BasicServiceProvider(),
					new BasicIdentityProvider("urn-x:testid"));

			assertEquals("Round-trip handle validation failed.", principal.getName(), "testprincipal");

		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (NameIdentifierMappingException e) {
			fail("Error exercising NameMaper: " + e.getMessage());
		} catch (Exception e) {
			fail("Error exercising NameMaper: " + e.getMessage());
		}
	}

	public void testMemoryMappingBadQualifier() {

		try {

			NameMapper nameMapper = new NameMapper();

			String rawConfig = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
					+ "<NameMapping xmlns=\"urn:mace:shibboleth:namemapper:1.0\""
					+ "		xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
					+ "		xsi:schemaLocation=\"urn:mace:shibboleth:namemapper:1.0 namemapper.xsd\" "
					+ "			id=\"memorytest\" " + "		format=\"urn:mace:shibboleth:1.0:nameIdentifier\""
					+ "		type=\"SharedMemoryShibHandle\" handleTTL=\"1800\"/>";

			parser.parse(new InputSource(new StringReader(rawConfig)));
			nameMapper.addNameMapping(parser.getDocument().getDocumentElement());

			SAMLNameIdentifier nameId = nameMapper.getNameIdentifier("memory", new LocalPrincipal("testprincipal"),
					new BasicServiceProvider(), new BasicIdentityProvider("urn-x:good"));

			Principal principal = nameMapper.getPrincipal(nameId, new BasicServiceProvider(),
					new BasicIdentityProvider("urn-x:bad"));

			fail("Expected failure for bad name qualifier.");

		} catch (NameIdentifierMappingException e) {
			// This exception should be generated by this test

		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());

		} catch (Exception e) {
			fail("Error exercising NameMaper: " + e.getMessage());
		}
	}

	public void testPrincipalMapping() {

		try {

			NameMapper nameMapper = new NameMapper();

			String format = "urn-x:test:NameIdFormat1";
			String rawConfig = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
					+ "<NameMapping xmlns=\"urn:mace:shibboleth:namemapper:1.0\""
					+ "		xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
					+ "		xsi:schemaLocation=\"urn:mace:shibboleth:namemapper:1.0 namemapper.xsd\" " + "			format=\""
					+ format + "\"" + "		type=\"Principal\"/>";

			parser.parse(new InputSource(new StringReader(rawConfig)));
			nameMapper.addNameMapping(parser.getDocument().getDocumentElement());

			SAMLNameIdentifier nameId = new SAMLNameIdentifier("testprincipal", "urn-x:testid", format);
			Principal principal = nameMapper.getPrincipal(nameId, new BasicServiceProvider(),
					new BasicIdentityProvider("urn-x:testid"));

			assertEquals("Round-trip handle validation failed.", principal.getName(), "testprincipal");

		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (NameIdentifierMappingException e) {
			fail("Error exercising NameMaper: " + e.getMessage());
		} catch (Exception e) {
			fail("Error exercising NameMaper: " + e.getMessage());
		}

	}

	public void testPrincipalMappingBadQualifier() {

		try {

			NameMapper nameMapper = new NameMapper();

			String format = "urn-x:test:NameIdFormat1";
			String rawConfig = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
					+ "<NameMapping xmlns=\"urn:mace:shibboleth:namemapper:1.0\""
					+ "		xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
					+ "		xsi:schemaLocation=\"urn:mace:shibboleth:namemapper:1.0 namemapper.xsd\" " + "			format=\""
					+ format + "\"" + "		type=\"Principal\"/>";
			parser.parse(new InputSource(new StringReader(rawConfig)));
			nameMapper.addNameMapping(parser.getDocument().getDocumentElement());

			SAMLNameIdentifier nameId = new SAMLNameIdentifier("testprincipal", "urn-x:good", format);

			Principal principal = nameMapper.getPrincipal(nameId, new BasicServiceProvider(),
					new BasicIdentityProvider("urn-x:bad"));

			fail("Expected failure for bad name qualifier.");

		} catch (NameIdentifierMappingException e) {
			// This exception should be generated by this test

		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());

		} catch (Exception e) {
			fail("Error exercising NameMaper: " + e.getMessage());
		}

	}
}

class BasicIdentityProvider implements IdentityProvider {

	String id;

	public BasicIdentityProvider(String id) {

		this.id = id;
	}

	public String getProviderId() {

		return id;
	}

	public Credential getSigningCredential() {

		return null;
	}

	public boolean signAuthNAssertions() {

		return false;
	}

	public boolean signAuthNResponses() {

		return false;
	}

	public boolean signAttributeAssertions() {

		return false;
	}

	public boolean signAttributeResponses() {

		return false;
	}

}

class BasicServiceProvider implements ServiceProvider {

	public String getProviderId() {

		return null;
	}

}