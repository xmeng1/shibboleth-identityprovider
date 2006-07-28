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
import java.util.Arrays;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.opensaml.common.SAMLObjectTestCaseConfigInitializer;
import org.opensaml.common.xml.ParserPoolManager;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.security.TrustEngine;
import org.opensaml.security.X509EntityCredential;
import org.opensaml.security.impl.SimpleX509EntityCredential;
import org.opensaml.xml.Configuration;
import org.w3c.dom.Document;

import edu.internet2.middleware.shibboleth.common.ShibResource.ResourceNotAvailableException;
import edu.internet2.middleware.shibboleth.common.provider.ShibbolethTrustEngine;

/**
 * Test suite for SAML/Shibboleth trust validation.
 * 
 * @author Walter Hoehn
 */
public class TrustTests extends TestCase {

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

	public void testInlineX509CertValidate() {

		try {
			// Pull the role descriptor from example metadata
			MetadataProvider metadata = new FilesystemMetadataProvider(new File("data/metadata1.xml"));
			EntityDescriptor entity = metadata.getEntityDescriptor("urn-x:testSP1");
			SPSSODescriptor role = (SPSSODescriptor) entity.getSPSSODescriptor("urn:oasis:names:tc:SAML:1.1:protocol");

			// Use a pre-defined cert
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new ShibResource(new File("data/trusttest.jks").toURL().toString()).getInputStream(),
					new char[]{'t', 'e', 's', 't', '1', '2', '3'});
			X509Certificate cert = (X509Certificate) keyStore.getCertificate("inliine1");

			// Try to validate against the metadata
			TrustEngine<X509EntityCredential> validator = new ShibbolethTrustEngine();
			boolean successful = validator.validate(new SimpleX509EntityCredential(Arrays
					.asList(new X509Certificate[]{cert})), role);
			if (!successful) {
				fail("Validation should have succeeded.");
			}

		} catch (MetadataProviderException e) {
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
			MetadataProvider metadata = new FilesystemMetadataProvider(new File("data/metadata1.xml"));
			EntityDescriptor entity = metadata.getEntityDescriptor("urn-x:testSP1");
			SPSSODescriptor role = (SPSSODescriptor) entity.getSPSSODescriptor("urn:oasis:names:tc:SAML:1.1:protocol");

			// Use a pre-defined cert
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new ShibResource(new File("data/trusttest.jks").toURL().toString()).getInputStream(),
					new char[]{'t', 'e', 's', 't', '1', '2', '3'});
			X509Certificate cert = (X509Certificate) keyStore.getCertificate("inline2");

			// Try to validate against the metadata
			TrustEngine<X509EntityCredential> validator = new ShibbolethTrustEngine();
			boolean successful = validator.validate(new SimpleX509EntityCredential(Arrays
					.asList(new X509Certificate[]{cert})), role);
			if (successful) {
				fail("Validation should have failed.");
			}

		} catch (MetadataProviderException e) {
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
			MetadataProvider metadata = new FilesystemMetadataProvider(new File("data/metadata2.xml"));
			EntityDescriptor entity = metadata.getEntityDescriptor("urn-x:testSP1");
			SPSSODescriptor role = (SPSSODescriptor) entity.getSPSSODescriptor("urn:oasis:names:tc:SAML:1.1:protocol");

			// Use a pre-defined cert
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new ShibResource(new File("data/trusttest.jks").toURL().toString()).getInputStream(),
					new char[]{'t', 'e', 's', 't', '1', '2', '3'});
			X509Certificate cert = (X509Certificate) keyStore.getCertificate("inliine1");

			// Try to validate against the metadata
			TrustEngine<X509EntityCredential> validator = new ShibbolethTrustEngine();
			boolean successful = validator.validate(new SimpleX509EntityCredential(Arrays
					.asList(new X509Certificate[]{cert})), role);
			if (!successful) {
				fail("Validation should have succeeded.");
			}

		} catch (MetadataProviderException e) {
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
			MetadataProvider metadata = new FilesystemMetadataProvider(new File("data/metadata3.xml"));
			EntityDescriptor entity = metadata.getEntityDescriptor("urn-x:testSP1");
			SPSSODescriptor role = (SPSSODescriptor) entity.getSPSSODescriptor("urn:oasis:names:tc:SAML:1.1:protocol");

			// Use a pre-defined cert
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new ShibResource(new File("data/trusttest.jks").toURL().toString()).getInputStream(),
					new char[]{'t', 'e', 's', 't', '1', '2', '3'});
			X509Certificate cert = (X509Certificate) keyStore.getCertificate("inliine1");

			// Try to validate against the metadata
			TrustEngine<X509EntityCredential> validator = new ShibbolethTrustEngine();
			boolean successful = validator.validate(new SimpleX509EntityCredential(Arrays
					.asList(new X509Certificate[]{cert})), role);
			if (!successful) {
				fail("Validation should have succeeded.");
			}

		} catch (MetadataProviderException e) {
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
			MetadataProvider metadata = new FilesystemMetadataProvider(new File("data/metadata4.xml"));
			EntityDescriptor entity = metadata.getEntityDescriptor("urn-x:testSP1");
			SPSSODescriptor role = (SPSSODescriptor) entity.getSPSSODescriptor("urn:oasis:names:tc:SAML:1.1:protocol");

			// Use a pre-defined cert
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new ShibResource(new File("data/trusttest.jks").toURL().toString()).getInputStream(),
					new char[]{'t', 'e', 's', 't', '1', '2', '3'});
			X509Certificate cert = (X509Certificate) keyStore.getCertificate("inline3");

			// Try to validate against the metadata
			TrustEngine<X509EntityCredential> validator = new ShibbolethTrustEngine();
			boolean successful = validator.validate(new SimpleX509EntityCredential(Arrays
					.asList(new X509Certificate[]{cert})), role);
			if (!successful) {
				fail("Validation should have succeeded.");
			}

		} catch (MetadataProviderException e) {
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
			MetadataProvider metadata = new FilesystemMetadataProvider(new File("data/metadata11.xml"));
			EntityDescriptor entity = metadata.getEntityDescriptor("urn-x:testSP1");
			SPSSODescriptor role = (SPSSODescriptor) entity.getSPSSODescriptor("urn:oasis:names:tc:SAML:1.1:protocol");

			// Use a pre-defined cert
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new ShibResource(new File("data/trusttest.jks").toURL().toString()).getInputStream(),
					new char[]{'t', 'e', 's', 't', '1', '2', '3'});
			X509Certificate cert = (X509Certificate) keyStore.getCertificate("inline3");

			// Try to validate against the metadata
			TrustEngine<X509EntityCredential> validator = new ShibbolethTrustEngine();
			boolean successful = validator.validate(new SimpleX509EntityCredential(Arrays
					.asList(new X509Certificate[]{cert})), role);
			if (successful) {
				fail("Validation should have failed.  DN in cert does not match the metadata.");
			}

		} catch (MetadataProviderException e) {
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
			MetadataProvider metadata = new FilesystemMetadataProvider(new File("data/metadata6.xml"));
			EntityDescriptor entity = metadata.getEntityDescriptor("urn-x:testSP1");
			SPSSODescriptor role = (SPSSODescriptor) entity.getSPSSODescriptor("urn:oasis:names:tc:SAML:1.1:protocol");

			// Use a pre-defined cert
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new ShibResource(new File("data/trusttest.jks").toURL().toString()).getInputStream(),
					new char[]{'t', 'e', 's', 't', '1', '2', '3'});
			X509Certificate endEntity = (X509Certificate) keyStore.getCertificate("inline3");
			X509Certificate intermediate = (X509Certificate) keyStore.getCertificate("im");

			// Try to validate against the metadata
			TrustEngine<X509EntityCredential> validator = new ShibbolethTrustEngine();
			boolean successful = validator.validate(new SimpleX509EntityCredential(Arrays.asList(new X509Certificate[]{
					endEntity, intermediate})), role);
			if (successful) {
				fail("Validation should not have succeeded.");
			}

		} catch (MetadataProviderException e) {
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
			MetadataProvider metadata = new FilesystemMetadataProvider(new File("data/metadata5.xml"));
			EntityDescriptor entity = metadata.getEntityDescriptor("urn-x:testSP1");
			SPSSODescriptor role = (SPSSODescriptor) entity.getSPSSODescriptor("urn:oasis:names:tc:SAML:1.1:protocol");

			// Use a pre-defined cert
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new ShibResource(new File("data/trusttest.jks").toURL().toString()).getInputStream(),
					new char[]{'t', 'e', 's', 't', '1', '2', '3'});
			X509Certificate endEntity = (X509Certificate) keyStore.getCertificate("inline3");
			X509Certificate intermediate = (X509Certificate) keyStore.getCertificate("im");

			// Try to validate against the metadata
			TrustEngine<X509EntityCredential> validator = new ShibbolethTrustEngine();
			boolean successful = validator.validate(new SimpleX509EntityCredential(Arrays.asList(new X509Certificate[]{
					endEntity, intermediate})), role);
			if (!successful) {
				fail("Validation should have succeeded.");
			}

		} catch (MetadataProviderException e) {
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
			MetadataProvider metadata = new FilesystemMetadataProvider(new File("data/metadata7.xml"));
			EntityDescriptor entity = metadata.getEntityDescriptor("urn-x:testSP1");
			SPSSODescriptor role = (SPSSODescriptor) entity.getSPSSODescriptor("urn:oasis:names:tc:SAML:1.1:protocol");

			// Use a pre-defined cert
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new ShibResource(new File("data/trusttest.jks").toURL().toString()).getInputStream(),
					new char[]{'t', 'e', 's', 't', '1', '2', '3'});
			X509Certificate cert = (X509Certificate) keyStore.getCertificate("inline4");

			// Try to validate against the metadata
			TrustEngine<X509EntityCredential> validator = new ShibbolethTrustEngine();
			boolean successful = validator.validate(new SimpleX509EntityCredential(Arrays
					.asList(new X509Certificate[]{cert})), role);
			if (successful) {
				fail("Validation should not have succeeded.");
			}

		} catch (MetadataProviderException e) {
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
			MetadataProvider metadata = new FilesystemMetadataProvider(new File("data/metadata8.xml"));
			EntityDescriptor entity = metadata.getEntityDescriptor("urn-x:testSP1");
			SPSSODescriptor role = (SPSSODescriptor) entity.getSPSSODescriptor("urn:oasis:names:tc:SAML:1.1:protocol");

			// Use a pre-defined cert
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new ShibResource(new File("data/trusttest.jks").toURL().toString()).getInputStream(),
					new char[]{'t', 'e', 's', 't', '1', '2', '3'});
			X509Certificate cert = (X509Certificate) keyStore.getCertificate("inline4");

			// Try to validate against the metadata
			TrustEngine<X509EntityCredential> validator = new ShibbolethTrustEngine();
			boolean successful = validator.validate(new SimpleX509EntityCredential(Arrays
					.asList(new X509Certificate[]{cert})), role);
			if (!successful) {
				fail("Validation should have succeeded.");
			}

		} catch (MetadataProviderException e) {
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
			MetadataProvider metadata = new FilesystemMetadataProvider(new File("data/metadata9.xml"));
			EntityDescriptor entity = metadata.getEntityDescriptor("Walter Hoehn");
			SPSSODescriptor role = (SPSSODescriptor) entity.getSPSSODescriptor("urn:oasis:names:tc:SAML:1.1:protocol");

			// Use a pre-defined cert
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new ShibResource(new File("data/trusttest.jks").toURL().toString()).getInputStream(),
					new char[]{'t', 'e', 's', 't', '1', '2', '3'});
			X509Certificate cert = (X509Certificate) keyStore.getCertificate("inliine1");

			// Try to validate against the metadata
			TrustEngine<X509EntityCredential> validator = new ShibbolethTrustEngine();
			boolean successful = validator.validate(new SimpleX509EntityCredential(Arrays
					.asList(new X509Certificate[]{cert})), role);
			if (!successful) {
				fail("Validation should have succeeded.");
			}

		} catch (MetadataProviderException e) {
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