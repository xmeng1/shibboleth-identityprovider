/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
 * provided with the distribution, if any, must include the following acknowledgment: "This product includes software
 * developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu> Internet2 Project.
 * Alternately, this acknowledegement may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear. Neither the name of Shibboleth nor the names of its contributors, nor Internet2, nor
 * the University Corporation for Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote
 * products derived from this software without specific prior written permission. For written permission, please contact
 * shibboleth@shibboleth.org Products derived from this software may not be called Shibboleth, Internet2, UCAID, or the
 * University Corporation for Advanced Internet Development, nor may Shibboleth appear in their name, without prior
 * written permission of the University Corporation for Advanced Internet Development. THIS SOFTWARE IS PROVIDED BY THE
 * COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE
 * DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. IN NO
 * EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC.
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.hs.provider;

import java.io.File;
import java.io.StringReader;
import java.net.MalformedURLException;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.opensaml.SAMLNameIdentifier;
import org.xml.sax.InputSource;

import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;
import edu.internet2.middleware.shibboleth.common.Credential;
import edu.internet2.middleware.shibboleth.common.IdentityProvider;
import edu.internet2.middleware.shibboleth.common.InvalidNameIdentifierException;
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
		Logger.getRootLogger().setLevel(Level.DEBUG);
	}

	public static void main(String[] args) {

		junit.textui.TestRunner.run(NameMapperTests.class);
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.DEBUG);
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

			SAMLNameIdentifier nameId = nameMapper.getNameIdentifierName("cryptotest", new AuthNPrincipal(
					"testprincipal"), new BasicServiceProvider(), new BasicIdentityProvider("urn-x:testid"));

			AuthNPrincipal principal = nameMapper.getPrincipal(nameId, new BasicServiceProvider(),
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

			SAMLNameIdentifier nameId = nameMapper.getNameIdentifierName("cryptotest", new AuthNPrincipal(
					"testprincipal"), new BasicServiceProvider(), new BasicIdentityProvider("urn-x:testid"));

			log.debug("Waiting 11 seconds for the handle to expire.");
			Thread.sleep(22000);

			AuthNPrincipal principal = nameMapper.getPrincipal(nameId, new BasicServiceProvider(),
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

			SAMLNameIdentifier nameId = nameMapper.getNameIdentifierName("cryptotest", new AuthNPrincipal(
					"testprincipal"), new BasicServiceProvider(), new BasicIdentityProvider("urn-x:testid"));

			AuthNPrincipal principal = nameMapper.getPrincipal(nameId, new BasicServiceProvider(),
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

			SAMLNameIdentifier nameId = nameMapper.getNameIdentifierName("cryptotest", new AuthNPrincipal(
					"testprincipal"), new BasicServiceProvider(), new BasicIdentityProvider("urn-x:good"));

			AuthNPrincipal principal = nameMapper.getPrincipal(nameId, new BasicServiceProvider(),
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

			SAMLNameIdentifier nameId = nameMapper.getNameIdentifierName(null, new AuthNPrincipal("testprincipal"),
					new BasicServiceProvider(), new BasicIdentityProvider("urn-x:testid"));

			AuthNPrincipal principal = nameMapper.getPrincipal(nameId, new BasicServiceProvider(),
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

			SAMLNameIdentifier nameId = nameMapper.getNameIdentifierName(null, new AuthNPrincipal("testprincipal"),
					new BasicServiceProvider(), new BasicIdentityProvider("urn-x:testid"));

			AuthNPrincipal principal = nameMapper.getPrincipal(nameId, new BasicServiceProvider(),
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

			nameMapper.getNameIdentifierName(null, new AuthNPrincipal("testprincipal"), new BasicServiceProvider(),
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

			SAMLNameIdentifier nameId = nameMapper.getNameIdentifierName("memorytest", new AuthNPrincipal(
					"testprincipal"), new BasicServiceProvider(), new BasicIdentityProvider("urn-x:testid"));

			AuthNPrincipal principal = nameMapper.getPrincipal(nameId, new BasicServiceProvider(),
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

			SAMLNameIdentifier nameId = nameMapper.getNameIdentifierName("memory", new AuthNPrincipal("testprincipal"),
					new BasicServiceProvider(), new BasicIdentityProvider("urn-x:good"));

			AuthNPrincipal principal = nameMapper.getPrincipal(nameId, new BasicServiceProvider(),
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
			AuthNPrincipal principal = nameMapper.getPrincipal(nameId, new BasicServiceProvider(),
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

			AuthNPrincipal principal = nameMapper.getPrincipal(nameId, new BasicServiceProvider(),
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