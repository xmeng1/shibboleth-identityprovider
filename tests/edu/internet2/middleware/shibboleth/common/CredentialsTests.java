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

package edu.internet2.middleware.shibboleth.common;

import java.io.FileInputStream;
import java.io.InputStream;

import javax.xml.parsers.DocumentBuilderFactory;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.xml.sax.InputSource;

/**
 * Validation suite for the <code>Credentials</code> interface.
 * 
 * @author Walter Hoehn
 */

public class CredentialsTests extends TestCase {

	public CredentialsTests(String name) {

		super(name);
		BasicConfigurator.resetConfiguration();
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	public static void main(String[] args) {

		junit.textui.TestRunner.run(CredentialsTests.class);
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	/**
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {

		super.setUp();
	}

	public void testKeyStoreX509CompleteChain() {

		try {
			InputStream inStream = new FileInputStream("data/credentials1.xml");
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);

			Credentials credentials = new Credentials(factory.newDocumentBuilder().parse(new InputSource(inStream))
					.getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue("Credential was loaded with an incorrect type.",
					credential.getCredentialType() == Credential.RSA);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals("Unexpected X509 certificate found.",
					credential.getX509Certificate().getSubjectDN().getName(),
					"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals("Unexpected certificate chain length.", new Integer(
					credential.getX509CertificateChain().length), new Integer(3));
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

	public void testFileX509EndOnly() {

		try {
			InputStream inStream = new FileInputStream("data/credentials16.xml");
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);

			Credentials credentials = new Credentials(factory.newDocumentBuilder().parse(new InputSource(inStream))
					.getDocumentElement());
			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue("Credential was loaded with an incorrect type.",
					credential.getCredentialType() == Credential.RSA);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals("Unexpected X509 certificate found.",
					credential.getX509Certificate().getSubjectDN().getName(),
					"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals("Unexpected certificate chain length.", new Integer(
					credential.getX509CertificateChain().length), new Integer(1));
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testFileX509IncompleteChain() {

		try {
			InputStream inStream = new FileInputStream("data/credentials17.xml");
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);

			Credentials credentials = new Credentials(factory.newDocumentBuilder().parse(new InputSource(inStream))
					.getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue("Credential was loaded with an incorrect type.",
					credential.getCredentialType() == Credential.RSA);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals("Unexpected X509 certificate found.",
					credential.getX509Certificate().getSubjectDN().getName(),
					"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals("Unexpected certificate chain length.", new Integer(
					credential.getX509CertificateChain().length), new Integer(2));
			assertEquals(
					"Unexpected X509 certificate found.",
					credential.getX509CertificateChain()[1].getSubjectDN().getName(),
					"CN=HEPKI Server CA -- 20020701A, OU=Division of Information Technology, O=University of Wisconsin, L=Madison, ST=Wisconsin, C=US");
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testFileX509RSANoCert() {

		try {
			InputStream inStream = new FileInputStream("data/credentials18.xml");
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);

			Credentials credentials = new Credentials(factory.newDocumentBuilder().parse(new InputSource(inStream))
					.getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue("Credential was loaded with an incorrect type.",
					credential.getCredentialType() == Credential.RSA);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals("Unexpected X509 certificate found.", credential.hasX509Certificate(), false);
			assertEquals("Unexpected certificate chain length.", new Integer(
					credential.getX509CertificateChain().length), new Integer(0));
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testKeyStoreX509AliasDefaulting() {

		try {
			InputStream inStream = new FileInputStream("data/credentials3.xml");
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);

			Credentials credentials = new Credentials(factory.newDocumentBuilder().parse(new InputSource(inStream))
					.getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue("Credential was loaded with an incorrect type.",
					credential.getCredentialType() == Credential.RSA);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals("Unexpected X509 certificate found.",
					credential.getX509Certificate().getSubjectDN().getName(),
					"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals("Unexpected certificate chain length.", new Integer(
					credential.getX509CertificateChain().length), new Integer(3));
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
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);

			Credentials credentials = new Credentials(factory.newDocumentBuilder().parse(new InputSource(inStream))
					.getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue("Credential was loaded with an incorrect type.",
					credential.getCredentialType() == Credential.RSA);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals("Unexpected X509 certificate found.",
					credential.getX509Certificate().getSubjectDN().getName(),
					"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals("Unexpected certificate chain length.", new Integer(
					credential.getX509CertificateChain().length), new Integer(3));
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
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);

			Credentials credentials = new Credentials(factory.newDocumentBuilder().parse(new InputSource(inStream))
					.getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue("Credential was loaded with an incorrect type.",
					credential.getCredentialType() == Credential.RSA);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals("Unexpected X509 certificate found.",
					credential.getX509Certificate().getSubjectDN().getName(),
					"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals("Unexpected certificate chain length.", new Integer(
					credential.getX509CertificateChain().length), new Integer(3));
			assertEquals(
					"Unexpected X509 certificate found.",
					credential.getX509CertificateChain()[2].getSubjectDN().getName(),
					"CN=HEPKI Master CA -- 20020701A, OU=Division of Information Technology, O=University of Wisconsin, L=Madison, ST=Wisconsin, C=US");
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testFileX509_PEM_PKCS8Key() {

		try {
			InputStream inStream = new FileInputStream("data/credentials5.xml");
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);

			Credentials credentials = new Credentials(factory.newDocumentBuilder().parse(new InputSource(inStream))
					.getDocumentElement());
			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue("Credential was loaded with an incorrect type.",
					credential.getCredentialType() == Credential.RSA);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals("Unexpected X509 certificate found.",
					credential.getX509Certificate().getSubjectDN().getName(),
					"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals("Unexpected certificate chain length.", new Integer(
					credential.getX509CertificateChain().length), new Integer(3));
			assertEquals(
					"Unexpected X509 certificate found.",
					credential.getX509CertificateChain()[2].getSubjectDN().getName(),
					"CN=HEPKI Master CA -- 20020701A, OU=Division of Information Technology, O=University of Wisconsin, L=Madison, ST=Wisconsin, C=US");
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testFileX509_DER_RSA_Key() {

		try {
			InputStream inStream = new FileInputStream("data/credentials6.xml");
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);

			Credentials credentials = new Credentials(factory.newDocumentBuilder().parse(new InputSource(inStream))
					.getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue("Credential was loaded with an incorrect type.",
					credential.getCredentialType() == Credential.RSA);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals("Unexpected X509 certificate found.",
					credential.getX509Certificate().getSubjectDN().getName(),
					"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals("Unexpected certificate chain length.", new Integer(
					credential.getX509CertificateChain().length), new Integer(3));
			assertEquals(
					"Unexpected X509 certificate found.",
					credential.getX509CertificateChain()[2].getSubjectDN().getName(),
					"CN=HEPKI Master CA -- 20020701A, OU=Division of Information Technology, O=University of Wisconsin, L=Madison, ST=Wisconsin, C=US");
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testFileX509_PEM_RSA_Key() {

		try {
			InputStream inStream = new FileInputStream("data/credentials7.xml");
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);

			Credentials credentials = new Credentials(factory.newDocumentBuilder().parse(new InputSource(inStream))
					.getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue("Credential was loaded with an incorrect type.",
					credential.getCredentialType() == Credential.RSA);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals("Unexpected X509 certificate found.",
					credential.getX509Certificate().getSubjectDN().getName(),
					"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals("Unexpected certificate chain length.", new Integer(
					credential.getX509CertificateChain().length), new Integer(3));
			assertEquals(
					"Unexpected X509 certificate found.",
					credential.getX509CertificateChain()[2].getSubjectDN().getName(),
					"CN=HEPKI Master CA -- 20020701A, OU=Division of Information Technology, O=University of Wisconsin, L=Madison, ST=Wisconsin, C=US");
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testFileX509_DER_DSA_Key() {

		try {
			InputStream inStream = new FileInputStream("data/credentials8.xml");
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);

			Credentials credentials = new Credentials(factory.newDocumentBuilder().parse(new InputSource(inStream))
					.getDocumentElement());
			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue("Credential was loaded with an incorrect type.",
					credential.getCredentialType() == Credential.DSA);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals("Unexpected X509 certificate found.",
					credential.getX509Certificate().getSubjectDN().getName(),
					"CN=test.columbia.edu, OU=ACIS, O=Columbia University, L=New York, ST=NY, C=US");
			assertEquals("Unexpected certificate chain length.", new Integer(
					credential.getX509CertificateChain().length), new Integer(1));
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testFileX509_PEM_DSA_Key() {

		try {
			InputStream inStream = new FileInputStream("data/credentials9.xml");
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);

			Credentials credentials = new Credentials(factory.newDocumentBuilder().parse(new InputSource(inStream))
					.getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue("Credential was loaded with an incorrect type.",
					credential.getCredentialType() == Credential.DSA);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals("Unexpected X509 certificate found.",
					credential.getX509Certificate().getSubjectDN().getName(),
					"CN=test.columbia.edu, OU=ACIS, O=Columbia University, L=New York, ST=NY, C=US");
			assertEquals("Unexpected certificate chain length.", new Integer(
					credential.getX509CertificateChain().length), new Integer(1));
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testFileX509_PEM_PKCS8_DSA_Key() {

		try {
			InputStream inStream = new FileInputStream("data/credentials10.xml");
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);

			Credentials credentials = new Credentials(factory.newDocumentBuilder().parse(new InputSource(inStream))
					.getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue("Credential was loaded with an incorrect type.",
					credential.getCredentialType() == Credential.DSA);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals("Unexpected X509 certificate found.",
					credential.getX509Certificate().getSubjectDN().getName(),
					"CN=test.columbia.edu, OU=ACIS, O=Columbia University, L=New York, ST=NY, C=US");
			assertEquals("Unexpected certificate chain length.", new Integer(
					credential.getX509CertificateChain().length), new Integer(1));
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testFileX509_DER_PKCS8_Encrypted_RSA_Key() {

		try {
			InputStream inStream = new FileInputStream("data/credentials11.xml");
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);

			Credentials credentials = new Credentials(factory.newDocumentBuilder().parse(new InputSource(inStream))
					.getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue("Credential was loaded with an incorrect type.",
					credential.getCredentialType() == Credential.RSA);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals("Unexpected X509 certificate found.",
					credential.getX509Certificate().getSubjectDN().getName(),
					"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals("Unexpected certificate chain length.", new Integer(
					credential.getX509CertificateChain().length), new Integer(3));
			assertEquals(
					"Unexpected X509 certificate found.",
					credential.getX509CertificateChain()[2].getSubjectDN().getName(),
					"CN=HEPKI Master CA -- 20020701A, OU=Division of Information Technology, O=University of Wisconsin, L=Madison, ST=Wisconsin, C=US");
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testFileX509_PEM_PKCS8_Encrypted_RSA_Key() {

		try {
			InputStream inStream = new FileInputStream("data/credentials12.xml");
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);

			Credentials credentials = new Credentials(factory.newDocumentBuilder().parse(new InputSource(inStream))
					.getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue("Credential was loaded with an incorrect type.",
					credential.getCredentialType() == Credential.RSA);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals("Unexpected X509 certificate found.",
					credential.getX509Certificate().getSubjectDN().getName(),
					"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals("Unexpected certificate chain length.", new Integer(
					credential.getX509CertificateChain().length), new Integer(3));
			assertEquals(
					"Unexpected X509 certificate found.",
					credential.getX509CertificateChain()[2].getSubjectDN().getName(),
					"CN=HEPKI Master CA -- 20020701A, OU=Division of Information Technology, O=University of Wisconsin, L=Madison, ST=Wisconsin, C=US");
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testFileX509_PEM_Encrypted_DES_RSA_Key() {

		try {
			InputStream inStream = new FileInputStream("data/credentials14.xml");
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);

			Credentials credentials = new Credentials(factory.newDocumentBuilder().parse(new InputSource(inStream))
					.getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue("Credential was loaded with an incorrect type.",
					credential.getCredentialType() == Credential.RSA);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals("Unexpected X509 certificate found.",
					credential.getX509Certificate().getSubjectDN().getName(),
					"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals("Unexpected certificate chain length.", new Integer(
					credential.getX509CertificateChain().length), new Integer(3));
			assertEquals(
					"Unexpected X509 certificate found.",
					credential.getX509CertificateChain()[2].getSubjectDN().getName(),
					"CN=HEPKI Master CA -- 20020701A, OU=Division of Information Technology, O=University of Wisconsin, L=Madison, ST=Wisconsin, C=US");
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testFileX509_PEM_Encrypted_TripeDES_RSA_Key() {

		try {
			InputStream inStream = new FileInputStream("data/credentials13.xml");
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);

			Credentials credentials = new Credentials(factory.newDocumentBuilder().parse(new InputSource(inStream))
					.getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue("Credential was loaded with an incorrect type.",
					credential.getCredentialType() == Credential.RSA);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals("Unexpected X509 certificate found.",
					credential.getX509Certificate().getSubjectDN().getName(),
					"CN=shib2.internet2.edu, OU=Unknown, O=Unknown, ST=Unknown, C=Unknown");
			assertEquals("Unexpected certificate chain length.", new Integer(
					credential.getX509CertificateChain().length), new Integer(3));
			assertEquals(
					"Unexpected X509 certificate found.",
					credential.getX509CertificateChain()[2].getSubjectDN().getName(),
					"CN=HEPKI Master CA -- 20020701A, OU=Division of Information Technology, O=University of Wisconsin, L=Madison, ST=Wisconsin, C=US");
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

	public void testFileX509_PEM_Encrypted_TripeDES_DSA_Key() {

		try {
			InputStream inStream = new FileInputStream("data/credentials15.xml");
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);

			Credentials credentials = new Credentials(factory.newDocumentBuilder().parse(new InputSource(inStream))
					.getDocumentElement());

			assertTrue("Credential could not be found.", credentials.containsCredential("test"));
			Credential credential = credentials.getCredential("test");

			assertTrue("Credential was loaded with an incorrect type.",
					credential.getCredentialType() == Credential.DSA);
			assertNotNull("Private key was not loaded correctly.", credential.getPrivateKey());
			assertEquals("Unexpected X509 certificate found.",
					credential.getX509Certificate().getSubjectDN().getName(),
					"CN=test.columbia.edu, OU=ACIS, O=Columbia University, L=New York, ST=NY, C=US");
			assertEquals("Unexpected certificate chain length.", new Integer(
					credential.getX509CertificateChain().length), new Integer(1));
		} catch (Exception e) {
			fail("Failed to load credentials: " + e);
		}
	}

}
