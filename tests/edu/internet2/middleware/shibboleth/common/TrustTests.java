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
import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;
import edu.internet2.middleware.shibboleth.metadata.KeyDescriptor;
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

	private Parser.DOMParser	parser	= new Parser.DOMParser(true);

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
			Trust validator = new Trust();
			boolean successful = validator.validate(role, new X509Certificate[]{cert}, KeyDescriptor.ENCRYPTION);
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
			Trust validator = new Trust();
			boolean successful = validator.validate(role, new X509Certificate[]{cert}, KeyDescriptor.ENCRYPTION);
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
			boolean successful = validator.validate(role, new X509Certificate[]{cert}, KeyDescriptor.ENCRYPTION);
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
			boolean successful = validator.validate(role, new X509Certificate[]{cert}, KeyDescriptor.ENCRYPTION);
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
	
	public void testPkixX509CertValidateWithCAs() {
		Logger.getRootLogger().setLevel(Level.DEBUG);
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
			boolean successful = validator.validate(role, new X509Certificate[]{cert}, KeyDescriptor.ENCRYPTION);
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
		Logger.getRootLogger().setLevel(Level.OFF);
	}
}