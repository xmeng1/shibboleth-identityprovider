/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.] Licensed under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in
 * writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.common;

import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import edu.internet2.middleware.shibboleth.common.ShibResource.ResourceNotAvailableException;
import edu.internet2.middleware.shibboleth.common.provider.BasicTrust;
import edu.internet2.middleware.shibboleth.common.provider.ShibbolethTrust;
import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;
import edu.internet2.middleware.shibboleth.metadata.Metadata;
import edu.internet2.middleware.shibboleth.metadata.MetadataException;
import edu.internet2.middleware.shibboleth.metadata.SPSSODescriptor;
import edu.internet2.middleware.shibboleth.metadata.provider.XMLMetadata;
import edu.internet2.middleware.shibboleth.xml.Parser;

/**
 * Test suite for SAML/Shibboleth trust validation.
 * 
 * @author Walter Hoehn
 */
public class TrustTests extends TestCase {

	private Parser.DOMParser parser = new Parser.DOMParser(true);

	public TrustTests(String name) {

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

	protected void setUp() throws Exception {

		super.setUp();
	}

	public void testInlineX509CertValidate() {

		try {
			// Pull the role descriptor from example metadata
			Metadata metadata = new XMLMetadata(new File("data/metadata1.xml").toURL().toString());
			EntityDescriptor entity = metadata.lookup("urn-x:testSP1");
			SPSSODescriptor role = (SPSSODescriptor) entity.getRoleByType(SPSSODescriptor.class,
					"urn:oasis:names:tc:SAML:1.1:protocol");

			// Use a pre-defined cert
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new ShibResource(new File("data/trusttest.jks").toURL().toString()).getInputStream(),
					new char[]{'t', 'e', 's', 't', '1', '2', '3'});
			X509Certificate cert = (X509Certificate) keyStore.getCertificate("inliine1");

			// Try to validate against the metadata
			Trust validator = new BasicTrust();
			boolean successful = validator.validate(cert, new X509Certificate[]{cert}, role);
			if (!successful) {
				fail("Validation should have succeeded.");
			}

		} catch (MetadataException e) {
			fail("Error in test specification: " + e);
		} catch (ResourceNotAvailableException e) {
			fail("Error in test specification: " + e);
		} catch (IOException e) {
			fail("Error in test specification: " + e);
		} catch (NoSuchAlgorithmException e) {
			fail("Error in test specification: " + e);
		} catch (CertificateException e) {
			fail("Error in test specification: " + e);
		} catch (KeyStoreException e) {
			fail("Error in test specification: " + e);
		}
	}

	public void testInlineX509CertValidationFail() {

		try {
			// Pull the role descriptor from example metadata
			Metadata metadata = new XMLMetadata(new File("data/metadata1.xml").toURL().toString());
			EntityDescriptor entity = metadata.lookup("urn-x:testSP1");
			SPSSODescriptor role = (SPSSODescriptor) entity.getRoleByType(SPSSODescriptor.class,
					"urn:oasis:names:tc:SAML:1.1:protocol");

			// Use a pre-defined cert
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new ShibResource(new File("data/trusttest.jks").toURL().toString()).getInputStream(),
					new char[]{'t', 'e', 's', 't', '1', '2', '3'});
			X509Certificate cert = (X509Certificate) keyStore.getCertificate("inline2");

			// Try to validate against the metadata
			Trust validator = new BasicTrust();
			boolean successful = validator.validate(cert, new X509Certificate[]{cert}, role);
			if (successful) {
				fail("Validation should have failed.");
			}

		} catch (MetadataException e) {
			fail("Error in test specification: " + e);
		} catch (ResourceNotAvailableException e) {
			fail("Error in test specification: " + e);
		} catch (IOException e) {
			fail("Error in test specification: " + e);
		} catch (NoSuchAlgorithmException e) {
			fail("Error in test specification: " + e);
		} catch (CertificateException e) {
			fail("Error in test specification: " + e);
		} catch (KeyStoreException e) {
			fail("Error in test specification: " + e);
		}
	}

	public void testPkixX509CertValidate() {

		try {
			// Pull the role descriptor from example metadata
			Metadata metadata = new XMLMetadata(new File("data/metadata2.xml").toURL().toString());
			EntityDescriptor entity = metadata.lookup("urn-x:testSP1");
			SPSSODescriptor role = (SPSSODescriptor) entity.getRoleByType(SPSSODescriptor.class,
					"urn:oasis:names:tc:SAML:1.1:protocol");

			// Use a pre-defined cert
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new ShibResource(new File("data/trusttest.jks").toURL().toString()).getInputStream(),
					new char[]{'t', 'e', 's', 't', '1', '2', '3'});
			X509Certificate cert = (X509Certificate) keyStore.getCertificate("inliine1");

			// Try to validate against the metadata
			Trust validator = new ShibbolethTrust();
			boolean successful = validator.validate(cert, new X509Certificate[]{cert}, role);
			if (!successful) {
				fail("Validation should have succeeded.");
			}

		} catch (MetadataException e) {
			fail("Error in test specification: " + e);
		} catch (ResourceNotAvailableException e) {
			fail("Error in test specification: " + e);
		} catch (IOException e) {
			fail("Error in test specification: " + e);
		} catch (NoSuchAlgorithmException e) {
			fail("Error in test specification: " + e);
		} catch (CertificateException e) {
			fail("Error in test specification: " + e);
		} catch (KeyStoreException e) {
			fail("Error in test specification: " + e);
		}
	}

	public void testPkixX509CertValidateRecurseEntities() {

		try {
			// Pull the role descriptor from example metadata
			Metadata metadata = new XMLMetadata(new File("data/metadata3.xml").toURL().toString());
			EntityDescriptor entity = metadata.lookup("urn-x:testSP1");
			SPSSODescriptor role = (SPSSODescriptor) entity.getRoleByType(SPSSODescriptor.class,
					"urn:oasis:names:tc:SAML:1.1:protocol");

			// Use a pre-defined cert
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new ShibResource(new File("data/trusttest.jks").toURL().toString()).getInputStream(),
					new char[]{'t', 'e', 's', 't', '1', '2', '3'});
			X509Certificate cert = (X509Certificate) keyStore.getCertificate("inliine1");

			// Try to validate against the metadata
			Trust validator = new ShibbolethTrust();
			boolean successful = validator.validate(cert, new X509Certificate[]{cert}, role);
			if (!successful) {
				fail("Validation should have succeeded.");
			}

		} catch (MetadataException e) {
			fail("Error in test specification: " + e);
		} catch (ResourceNotAvailableException e) {
			fail("Error in test specification: " + e);
		} catch (IOException e) {
			fail("Error in test specification: " + e);
		} catch (NoSuchAlgorithmException e) {
			fail("Error in test specification: " + e);
		} catch (CertificateException e) {
			fail("Error in test specification: " + e);
		} catch (KeyStoreException e) {
			fail("Error in test specification: " + e);
		}
	}

	public void testPkixX509CertValidateWithCAPath() {

		try {
			// Pull the role descriptor from example metadata
			Metadata metadata = new XMLMetadata(new File("data/metadata4.xml").toURL().toString());
			EntityDescriptor entity = metadata.lookup("urn-x:testSP1");
			SPSSODescriptor role = (SPSSODescriptor) entity.getRoleByType(SPSSODescriptor.class,
					"urn:oasis:names:tc:SAML:1.1:protocol");

			// Use a pre-defined cert
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new ShibResource(new File("data/trusttest.jks").toURL().toString()).getInputStream(),
					new char[]{'t', 'e', 's', 't', '1', '2', '3'});
			X509Certificate cert = (X509Certificate) keyStore.getCertificate("inline3");

			// Try to validate against the metadata
			Trust validator = new ShibbolethTrust();
			boolean successful = validator.validate(cert, new X509Certificate[]{cert}, role);
			if (!successful) {
				fail("Validation should have succeeded.");
			}

		} catch (MetadataException e) {
			fail("Error in test specification: " + e);
		} catch (ResourceNotAvailableException e) {
			fail("Error in test specification: " + e);
		} catch (IOException e) {
			fail("Error in test specification: " + e);
		} catch (NoSuchAlgorithmException e) {
			fail("Error in test specification: " + e);
		} catch (CertificateException e) {
			fail("Error in test specification: " + e);
		} catch (KeyStoreException e) {
			fail("Error in test specification: " + e);
		}
	}

	public void testPkixX509CertFailBadNameMatch() {

		try {
			// Pull the role descriptor from example metadata
			Metadata metadata = new XMLMetadata(new File("data/metadata11.xml").toURL().toString());
			EntityDescriptor entity = metadata.lookup("urn-x:testSP1");
			SPSSODescriptor role = (SPSSODescriptor) entity.getRoleByType(SPSSODescriptor.class,
					"urn:oasis:names:tc:SAML:1.1:protocol");

			// Use a pre-defined cert
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new ShibResource(new File("data/trusttest.jks").toURL().toString()).getInputStream(),
					new char[]{'t', 'e', 's', 't', '1', '2', '3'});
			X509Certificate cert = (X509Certificate) keyStore.getCertificate("inline3");

			// Try to validate against the metadata
			Trust validator = new ShibbolethTrust();
			boolean successful = validator.validate(cert, new X509Certificate[]{cert}, role);
			if (successful) {
				fail("Validation should have failed.  DN in cert does not match the metadata.");
			}

		} catch (MetadataException e) {
			fail("Error in test specification: " + e);
		} catch (ResourceNotAvailableException e) {
			fail("Error in test specification: " + e);
		} catch (IOException e) {
			fail("Error in test specification: " + e);
		} catch (NoSuchAlgorithmException e) {
			fail("Error in test specification: " + e);
		} catch (CertificateException e) {
			fail("Error in test specification: " + e);
		} catch (KeyStoreException e) {
			fail("Error in test specification: " + e);
		}
	}

	public void testPkixX509CertFailValidateWithPathTooLong() {

		try {
			// Pull the role descriptor from example metadata
			Metadata metadata = new XMLMetadata(new File("data/metadata6.xml").toURL().toString());
			EntityDescriptor entity = metadata.lookup("urn-x:testSP1");
			SPSSODescriptor role = (SPSSODescriptor) entity.getRoleByType(SPSSODescriptor.class,
					"urn:oasis:names:tc:SAML:1.1:protocol");

			// Use a pre-defined cert
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new ShibResource(new File("data/trusttest.jks").toURL().toString()).getInputStream(),
					new char[]{'t', 'e', 's', 't', '1', '2', '3'});
			X509Certificate endEntity = (X509Certificate) keyStore.getCertificate("inline3");
			X509Certificate intermediate = (X509Certificate) keyStore.getCertificate("im");

			// Try to validate against the metadata
			Trust validator = new ShibbolethTrust();
			boolean successful = validator.validate(endEntity, new X509Certificate[]{endEntity, intermediate}, role);
			if (successful) {
				fail("Validation should not have succeeded.");
			}

		} catch (MetadataException e) {
			fail("Error in test specification: " + e);
		} catch (ResourceNotAvailableException e) {
			fail("Error in test specification: " + e);
		} catch (IOException e) {
			fail("Error in test specification: " + e);
		} catch (NoSuchAlgorithmException e) {
			fail("Error in test specification: " + e);
		} catch (CertificateException e) {
			fail("Error in test specification: " + e);
		} catch (KeyStoreException e) {
			fail("Error in test specification: " + e);
		}
	}

	public void testPkixX509CertValidateWithClientSuppliedIntermediate() {

		try {
			// Pull the role descriptor from example metadata
			Metadata metadata = new XMLMetadata(new File("data/metadata5.xml").toURL().toString());
			EntityDescriptor entity = metadata.lookup("urn-x:testSP1");
			SPSSODescriptor role = (SPSSODescriptor) entity.getRoleByType(SPSSODescriptor.class,
					"urn:oasis:names:tc:SAML:1.1:protocol");

			// Use a pre-defined cert
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new ShibResource(new File("data/trusttest.jks").toURL().toString()).getInputStream(),
					new char[]{'t', 'e', 's', 't', '1', '2', '3'});
			X509Certificate endEntity = (X509Certificate) keyStore.getCertificate("inline3");
			X509Certificate intermediate = (X509Certificate) keyStore.getCertificate("im");

			// Try to validate against the metadata
			Trust validator = new ShibbolethTrust();
			boolean successful = validator.validate(endEntity, new X509Certificate[]{endEntity, intermediate}, role);
			if (!successful) {
				fail("Validation should have succeeded.");
			}

		} catch (MetadataException e) {
			fail("Error in test specification: " + e);
		} catch (ResourceNotAvailableException e) {
			fail("Error in test specification: " + e);
		} catch (IOException e) {
			fail("Error in test specification: " + e);
		} catch (NoSuchAlgorithmException e) {
			fail("Error in test specification: " + e);
		} catch (CertificateException e) {
			fail("Error in test specification: " + e);
		} catch (KeyStoreException e) {
			fail("Error in test specification: " + e);
		}
	}

	public void testCRL() {

		try {
			// Pull the role descriptor from example metadata
			Metadata metadata = new XMLMetadata(new File("data/metadata7.xml").toURL().toString());
			EntityDescriptor entity = metadata.lookup("urn-x:testSP1");
			SPSSODescriptor role = (SPSSODescriptor) entity.getRoleByType(SPSSODescriptor.class,
					"urn:oasis:names:tc:SAML:1.1:protocol");

			// Use a pre-defined cert
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new ShibResource(new File("data/trusttest.jks").toURL().toString()).getInputStream(),
					new char[]{'t', 'e', 's', 't', '1', '2', '3'});
			X509Certificate cert = (X509Certificate) keyStore.getCertificate("inline4");

			// Try to validate against the metadata
			Trust validator = new ShibbolethTrust();
			boolean successful = validator.validate(cert, new X509Certificate[]{cert}, role);
			if (successful) {
				fail("Validation should not have succeeded.");
			}

		} catch (MetadataException e) {
			fail("Error in test specification: " + e);
		} catch (ResourceNotAvailableException e) {
			fail("Error in test specification: " + e);
		} catch (IOException e) {
			fail("Error in test specification: " + e);
		} catch (NoSuchAlgorithmException e) {
			fail("Error in test specification: " + e);
		} catch (CertificateException e) {
			fail("Error in test specification: " + e);
		} catch (KeyStoreException e) {
			fail("Error in test specification: " + e);
		}
	}

	public void testCRLDoesntBreakValid() {

		try {
			// Pull the role descriptor from example metadata
			Metadata metadata = new XMLMetadata(new File("data/metadata8.xml").toURL().toString());
			EntityDescriptor entity = metadata.lookup("urn-x:testSP1");
			SPSSODescriptor role = (SPSSODescriptor) entity.getRoleByType(SPSSODescriptor.class,
					"urn:oasis:names:tc:SAML:1.1:protocol");

			// Use a pre-defined cert
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new ShibResource(new File("data/trusttest.jks").toURL().toString()).getInputStream(),
					new char[]{'t', 'e', 's', 't', '1', '2', '3'});
			X509Certificate cert = (X509Certificate) keyStore.getCertificate("inline4");

			// Try to validate against the metadata
			Trust validator = new ShibbolethTrust();
			boolean successful = validator.validate(cert, new X509Certificate[]{cert}, role);
			if (!successful) {
				fail("Validation should have succeeded.");
			}

		} catch (MetadataException e) {
			fail("Error in test specification: " + e);
		} catch (ResourceNotAvailableException e) {
			fail("Error in test specification: " + e);
		} catch (IOException e) {
			fail("Error in test specification: " + e);
		} catch (NoSuchAlgorithmException e) {
			fail("Error in test specification: " + e);
		} catch (CertificateException e) {
			fail("Error in test specification: " + e);
		} catch (KeyStoreException e) {
			fail("Error in test specification: " + e);
		}
	}

	public void testPkixX509CertValidateWithExactProviderIdMatch() {

		try {
			// Pull the role descriptor from example metadata
			Metadata metadata = new XMLMetadata(new File("data/metadata9.xml").toURL().toString());
			EntityDescriptor entity = metadata.lookup("Walter Hoehn");
			SPSSODescriptor role = (SPSSODescriptor) entity.getRoleByType(SPSSODescriptor.class,
					"urn:oasis:names:tc:SAML:1.1:protocol");

			// Use a pre-defined cert
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new ShibResource(new File("data/trusttest.jks").toURL().toString()).getInputStream(),
					new char[]{'t', 'e', 's', 't', '1', '2', '3'});
			X509Certificate cert = (X509Certificate) keyStore.getCertificate("inliine1");

			// Try to validate against the metadata
			Trust validator = new ShibbolethTrust();
			boolean successful = validator.validate(cert, new X509Certificate[]{cert}, role);
			if (!successful) {
				fail("Validation should have succeeded.");
			}

		} catch (MetadataException e) {
			fail("Error in test specification: " + e);
		} catch (ResourceNotAvailableException e) {
			fail("Error in test specification: " + e);
		} catch (IOException e) {
			fail("Error in test specification: " + e);
		} catch (NoSuchAlgorithmException e) {
			fail("Error in test specification: " + e);
		} catch (CertificateException e) {
			fail("Error in test specification: " + e);
		} catch (KeyStoreException e) {
			fail("Error in test specification: " + e);
		}
	}

}