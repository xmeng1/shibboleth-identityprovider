/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved
 * 
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 * disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided with the distribution, if any, must include the
 * following acknowledgment: "This product includes software developed by the University Corporation for Advanced
 * Internet Development <http://www.ucaid.edu> Internet2 Project. Alternately, this acknowledegement may appear in the
 * software itself, if and wherever such third-party acknowledgments normally appear.
 * 
 * Neither the name of Shibboleth nor the names of its contributors, nor Internet2, nor the University Corporation for
 * Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote products derived from this software
 * without specific prior written permission. For written permission, please contact shibboleth@shibboleth.org
 * 
 * Products derived from this software may not be called Shibboleth, Internet2, UCAID, or the University Corporation
 * for Advanced Internet Development, nor may Shibboleth appear in their name, without prior written permission of the
 * University Corporation for Advanced Internet Development.
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE,
 * ACCURACY, AND EFFORT IS WITH LICENSEE. IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.common;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.xerces.parsers.DOMParser;
import org.xml.sax.EntityResolver;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/**
 * Validation suite for the <code>Credentials</code> interface.
 * 
 * @author Walter Hoehn
 */

public class CredentialsTests extends TestCase {

	private DOMParser parser = new DOMParser();

	public CredentialsTests(String name) {
		super(name);
		BasicConfigurator.resetConfiguration();
		BasicConfigurator.configure();
		//TODO turn this off later
		Logger.getRootLogger().setLevel(Level.DEBUG);
	}

	public static void main(String[] args) {
		junit.textui.TestRunner.run(CredentialsTests.class);
		BasicConfigurator.configure();
		//TODO turn this off later
		Logger.getRootLogger().setLevel(Level.DEBUG);
	}

	/**
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		super.setUp();
		try {
			parser.setFeature("http://xml.org/sax/features/validation", true);
			parser.setFeature("http://apache.org/xml/features/validation/schema", true);
			parser.setEntityResolver(new EntityResolver() {
				public InputSource resolveEntity(String publicId, String systemId) throws SAXException {

					if (systemId.endsWith("credentials.xsd")) {
						InputStream stream;
						try {
							stream = new FileInputStream("src/schemas/credentials.xsd");
							if (stream != null) {
								return new InputSource(stream);
							}
							throw new SAXException("Could not load entity: Null input stream");
						} catch (FileNotFoundException e) {
							throw new SAXException("Could not load entity: " + e);
						}
					} else if (systemId.endsWith("xmldsig-core-schema.xsd")) {
						InputStream stream;
						try {
							stream = new FileInputStream("src/schemas/xmldsig-core-schema.xsd");
							if (stream != null) {
								return new InputSource(stream);
							}
							throw new SAXException("Could not load entity: Null input stream");
						} catch (FileNotFoundException e) {
							throw new SAXException("Could not load entity: " + e);
						}
					} else {
						return null;
					}
				}
			});

			parser.setErrorHandler(new ErrorHandler() {
				public void error(SAXParseException arg0) throws SAXException {
					throw new SAXException("Error parsing xml file: " + arg0);
				}
				public void fatalError(SAXParseException arg0) throws SAXException {
					throw new SAXException("Error parsing xml file: " + arg0);
				}
				public void warning(SAXParseException arg0) throws SAXException {
					throw new SAXException("Error parsing xml file: " + arg0);
				}
			});
		} catch (Exception e) {
			fail("Failed to setup xml parser: " + e);
		}

	}

	public void testKeyStoreX509CompleteChain() {

		try {
			InputStream inStream = new FileInputStream("data/credentials1.xml");
			parser.parse(new InputSource(inStream));
			Credentials credentials = new Credentials(parser.getDocument().getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue(
				"Credential was loaded with an incorrect type.",
				credential.getCredentialType() == Credential.X509);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509Certificate().getSubjectDN().getName(),
				"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals(
				"Unexpected certificate chain length.",
				new Integer(credential.getX509CertificateChain().length),
				new Integer(3));
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509CertificateChain()[1].getSubjectDN().getName(),
				"CN=HEPKI Server CA -- 20020701A, OU=Division of Information Technology, O=University of Wisconsin, L=Madison, ST=Wisconsin, C=US");
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509CertificateChain()[2].getSubjectDN().getName(),
				"CN=HEPKI Master CA -- 20020701A, OU=Division of Information Technology, O=University of Wisconsin, L=Madison, ST=Wisconsin, C=US");
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testKeyStoreX509EndOnly() {

		try {
			InputStream inStream = new FileInputStream("data/credentials16.xml");
			parser.parse(new InputSource(inStream));
			Credentials credentials = new Credentials(parser.getDocument().getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue(
				"Credential was loaded with an incorrect type.",
				credential.getCredentialType() == Credential.X509);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509Certificate().getSubjectDN().getName(),
				"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals(
				"Unexpected certificate chain length.",
				new Integer(credential.getX509CertificateChain().length),
				new Integer(1));
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testKeyStoreX509IncompleteChain() {

		try {
			InputStream inStream = new FileInputStream("data/credentials17.xml");
			parser.parse(new InputSource(inStream));
			Credentials credentials = new Credentials(parser.getDocument().getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue(
				"Credential was loaded with an incorrect type.",
				credential.getCredentialType() == Credential.X509);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509Certificate().getSubjectDN().getName(),
				"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals(
				"Unexpected certificate chain length.",
				new Integer(credential.getX509CertificateChain().length),
				new Integer(2));
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509CertificateChain()[1].getSubjectDN().getName(),
				"CN=HEPKI Server CA -- 20020701A, OU=Division of Information Technology, O=University of Wisconsin, L=Madison, ST=Wisconsin, C=US");
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testKeyStoreX509AliasDefaulting() {

		try {
			InputStream inStream = new FileInputStream("data/credentials3.xml");
			parser.parse(new InputSource(inStream));
			Credentials credentials = new Credentials(parser.getDocument().getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue(
				"Credential was loaded with an incorrect type.",
				credential.getCredentialType() == Credential.X509);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509Certificate().getSubjectDN().getName(),
				"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals(
				"Unexpected certificate chain length.",
				new Integer(credential.getX509CertificateChain().length),
				new Integer(3));
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509CertificateChain()[2].getSubjectDN().getName(),
				"CN=HEPKI Master CA -- 20020701A, OU=Division of Information Technology, O=University of Wisconsin, L=Madison, ST=Wisconsin, C=US");
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testFileX509NoPassword() {

		try {
			InputStream inStream = new FileInputStream("data/credentials2.xml");
			parser.parse(new InputSource(inStream));
			Credentials credentials = new Credentials(parser.getDocument().getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue(
				"Credential was loaded with an incorrect type.",
				credential.getCredentialType() == Credential.X509);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509Certificate().getSubjectDN().getName(),
				"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals(
				"Unexpected certificate chain length.",
				new Integer(credential.getX509CertificateChain().length),
				new Integer(3));
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509CertificateChain()[2].getSubjectDN().getName(),
				"CN=HEPKI Master CA -- 20020701A, OU=Division of Information Technology, O=University of Wisconsin, L=Madison, ST=Wisconsin, C=US");
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testFileX509withCABundles() {

		try {
			InputStream inStream = new FileInputStream("data/credentials4.xml");
			parser.parse(new InputSource(inStream));
			Credentials credentials = new Credentials(parser.getDocument().getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue(
				"Credential was loaded with an incorrect type.",
				credential.getCredentialType() == Credential.X509);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509Certificate().getSubjectDN().getName(),
				"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals(
				"Unexpected certificate chain length.",
				new Integer(credential.getX509CertificateChain().length),
				new Integer(3));
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509CertificateChain()[2].getSubjectDN().getName(),
				"CN=HEPKI Master CA -- 20020701A, OU=Division of Information Technology, O=University of Wisconsin, L=Madison, ST=Wisconsin, C=US");
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testKeyStoreX509_PEM_PKCS8Key() {

		try {
			InputStream inStream = new FileInputStream("data/credentials5.xml");
			parser.parse(new InputSource(inStream));
			Credentials credentials = new Credentials(parser.getDocument().getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue(
				"Credential was loaded with an incorrect type.",
				credential.getCredentialType() == Credential.X509);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509Certificate().getSubjectDN().getName(),
				"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals(
				"Unexpected certificate chain length.",
				new Integer(credential.getX509CertificateChain().length),
				new Integer(3));
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509CertificateChain()[2].getSubjectDN().getName(),
				"CN=HEPKI Master CA -- 20020701A, OU=Division of Information Technology, O=University of Wisconsin, L=Madison, ST=Wisconsin, C=US");
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testKeyStoreX509_DER_RSA_Key() {

		try {
			InputStream inStream = new FileInputStream("data/credentials6.xml");
			parser.parse(new InputSource(inStream));
			Credentials credentials = new Credentials(parser.getDocument().getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue(
				"Credential was loaded with an incorrect type.",
				credential.getCredentialType() == Credential.X509);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509Certificate().getSubjectDN().getName(),
				"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals(
				"Unexpected certificate chain length.",
				new Integer(credential.getX509CertificateChain().length),
				new Integer(3));
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509CertificateChain()[2].getSubjectDN().getName(),
				"CN=HEPKI Master CA -- 20020701A, OU=Division of Information Technology, O=University of Wisconsin, L=Madison, ST=Wisconsin, C=US");
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testKeyStoreX509_PEM_RSA_Key() {

		try {
			InputStream inStream = new FileInputStream("data/credentials7.xml");
			parser.parse(new InputSource(inStream));
			Credentials credentials = new Credentials(parser.getDocument().getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue(
				"Credential was loaded with an incorrect type.",
				credential.getCredentialType() == Credential.X509);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509Certificate().getSubjectDN().getName(),
				"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals(
				"Unexpected certificate chain length.",
				new Integer(credential.getX509CertificateChain().length),
				new Integer(3));
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509CertificateChain()[2].getSubjectDN().getName(),
				"CN=HEPKI Master CA -- 20020701A, OU=Division of Information Technology, O=University of Wisconsin, L=Madison, ST=Wisconsin, C=US");
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testKeyStoreX509_DER_DSA_Key() {

		try {
			InputStream inStream = new FileInputStream("data/credentials8.xml");
			parser.parse(new InputSource(inStream));
			Credentials credentials = new Credentials(parser.getDocument().getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue(
				"Credential was loaded with an incorrect type.",
				credential.getCredentialType() == Credential.X509);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509Certificate().getSubjectDN().getName(),
				"CN=test.columbia.edu, OU=ACIS, O=Columbia University, L=New York, ST=NY, C=US");
			assertEquals(
				"Unexpected certificate chain length.",
				new Integer(credential.getX509CertificateChain().length),
				new Integer(1));
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testKeyStoreX509_PEM_DSA_Key() {

		try {
			InputStream inStream = new FileInputStream("data/credentials9.xml");
			parser.parse(new InputSource(inStream));
			Credentials credentials = new Credentials(parser.getDocument().getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue(
				"Credential was loaded with an incorrect type.",
				credential.getCredentialType() == Credential.X509);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509Certificate().getSubjectDN().getName(),
				"CN=test.columbia.edu, OU=ACIS, O=Columbia University, L=New York, ST=NY, C=US");
			assertEquals(
				"Unexpected certificate chain length.",
				new Integer(credential.getX509CertificateChain().length),
				new Integer(1));
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testKeyStoreX509_PEM_PKCS8_DSA_Key() {

		try {
			InputStream inStream = new FileInputStream("data/credentials10.xml");
			parser.parse(new InputSource(inStream));
			Credentials credentials = new Credentials(parser.getDocument().getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue(
				"Credential was loaded with an incorrect type.",
				credential.getCredentialType() == Credential.X509);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509Certificate().getSubjectDN().getName(),
				"CN=test.columbia.edu, OU=ACIS, O=Columbia University, L=New York, ST=NY, C=US");
			assertEquals(
				"Unexpected certificate chain length.",
				new Integer(credential.getX509CertificateChain().length),
				new Integer(1));
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testKeyStoreX509_DER_PKCS8_Encrypted_RSA_Key() {

		try {
			InputStream inStream = new FileInputStream("data/credentials11.xml");
			parser.parse(new InputSource(inStream));
			Credentials credentials = new Credentials(parser.getDocument().getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue(
				"Credential was loaded with an incorrect type.",
				credential.getCredentialType() == Credential.X509);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509Certificate().getSubjectDN().getName(),
				"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals(
				"Unexpected certificate chain length.",
				new Integer(credential.getX509CertificateChain().length),
				new Integer(3));
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509CertificateChain()[2].getSubjectDN().getName(),
				"CN=HEPKI Master CA -- 20020701A, OU=Division of Information Technology, O=University of Wisconsin, L=Madison, ST=Wisconsin, C=US");
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testKeyStoreX509_PEM_PKCS8_Encrypted_RSA_Key() {

		try {
			InputStream inStream = new FileInputStream("data/credentials12.xml");
			parser.parse(new InputSource(inStream));
			Credentials credentials = new Credentials(parser.getDocument().getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue(
				"Credential was loaded with an incorrect type.",
				credential.getCredentialType() == Credential.X509);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509Certificate().getSubjectDN().getName(),
				"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals(
				"Unexpected certificate chain length.",
				new Integer(credential.getX509CertificateChain().length),
				new Integer(3));
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509CertificateChain()[2].getSubjectDN().getName(),
				"CN=HEPKI Master CA -- 20020701A, OU=Division of Information Technology, O=University of Wisconsin, L=Madison, ST=Wisconsin, C=US");
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testKeyStoreX509_PEM_Encrypted_DES_RSA_Key() {

		try {
			InputStream inStream = new FileInputStream("data/credentials14.xml");
			parser.parse(new InputSource(inStream));
			Credentials credentials = new Credentials(parser.getDocument().getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue(
				"Credential was loaded with an incorrect type.",
				credential.getCredentialType() == Credential.X509);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509Certificate().getSubjectDN().getName(),
				"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals(
				"Unexpected certificate chain length.",
				new Integer(credential.getX509CertificateChain().length),
				new Integer(3));
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509CertificateChain()[2].getSubjectDN().getName(),
				"CN=HEPKI Master CA -- 20020701A, OU=Division of Information Technology, O=University of Wisconsin, L=Madison, ST=Wisconsin, C=US");
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testKeyStoreX509_PEM_Encrypted_TripeDES_RSA_Key() {

		try {
			InputStream inStream = new FileInputStream("data/credentials13.xml");
			parser.parse(new InputSource(inStream));
			Credentials credentials = new Credentials(parser.getDocument().getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue(
				"Credential was loaded with an incorrect type.",
				credential.getCredentialType() == Credential.X509);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509Certificate().getSubjectDN().getName(),
				"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals(
				"Unexpected certificate chain length.",
				new Integer(credential.getX509CertificateChain().length),
				new Integer(3));
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509CertificateChain()[2].getSubjectDN().getName(),
				"CN=HEPKI Master CA -- 20020701A, OU=Division of Information Technology, O=University of Wisconsin, L=Madison, ST=Wisconsin, C=US");
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testKeyStoreX509_PEM_Encrypted_TripeDES_DSA_Key() {

		try {
			InputStream inStream = new FileInputStream("data/credentials15.xml");
			parser.parse(new InputSource(inStream));
			Credentials credentials = new Credentials(parser.getDocument().getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue(
				"Credential was loaded with an incorrect type.",
				credential.getCredentialType() == Credential.X509);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals(
				"Unexpected X509 certificate found.",
				credential.getX509Certificate().getSubjectDN().getName(),
				"CN=test.columbia.edu, OU=ACIS, O=Columbia University, L=New York, ST=NY, C=US");
			assertEquals(
				"Unexpected certificate chain length.",
				new Integer(credential.getX509CertificateChain().length),
				new Integer(1));
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

}
