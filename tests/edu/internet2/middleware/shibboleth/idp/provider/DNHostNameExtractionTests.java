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

package edu.internet2.middleware.shibboleth.idp.provider;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import edu.internet2.middleware.shibboleth.common.ShibResource;
import edu.internet2.middleware.shibboleth.common.ShibResource.ResourceNotAvailableException;

/**
 * Validation suite for hack to pull hostnames out of a subject DN.
 * 
 * @author Walter Hoehn(wassa@columbia.edu)
 */
public class DNHostNameExtractionTests extends TestCase {

	// Basic
	String dn1 = "CN=wayf.internet2.edu,OU=TSG,O=University Corporation for Advanced Internet Development,L=Ann Arbor,ST=Michigan,C=US";

	// lowercase CN
	String dn2 = "cn=wayf.internet2.edu,OU=TSG,O=University Corporation for Advanced Internet Development,L=Ann Arbor,ST=Michigan,C=US";

	// Multiple CNs
	String dn4 = "CN=wayf.internet2.edu,OU=TSG, CN=foo, O=University Corporation for Advanced Internet Development,L=Ann Arbor,ST=Michigan,C=US";

	public DNHostNameExtractionTests(String name) {

		super(name);
		BasicConfigurator.resetConfiguration();
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	public static void main(String[] args) {

		junit.textui.TestRunner.run(DNHostNameExtractionTests.class);
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	protected void setUp() throws Exception {

		super.setUp();

	}

	public void testBasicExtraction() {

		try {
			assertEquals("Round-trip handle validation failed on DN.", BaseHandler.getHostNameFromDN(new X500Principal(
					dn1)), "wayf.internet2.edu");

		} catch (Exception e) {
			fail("Error in test specification: " + e.getMessage());
		}
	}

	public void testExtractionWithLowerCaseAttrName() {

		try {
			assertEquals("Round-trip handle validation failed on DN.", BaseHandler.getHostNameFromDN(new X500Principal(
					dn2)), "wayf.internet2.edu");

		} catch (Exception e) {
			fail("Error in test specification: " + e.getMessage());
		}
	}

	public void testExtractionWithMultipleCNs() {

		try {
			assertEquals("Round-trip handle validation failed on DN.", BaseHandler.getHostNameFromDN(new X500Principal(
					dn4)), "wayf.internet2.edu");

		} catch (Exception e) {
			fail("Error in test specification: " + e.getMessage());
		}
	}

	public void testExtractionWithStrangeDN() {

		try {
			// Use the cert referenced in bugzilla #143
			// This cert was breaking previously because of java's conversion of the dn to string form
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new ShibResource(new File("data/cnextract.jks").toURL().toString()).getInputStream(),
					new char[]{'t', 'e', 's', 't', '1', '2', '3'});
			X509Certificate cert = (X509Certificate) keyStore.getCertificate("scott");

			FileOutputStream output = new FileOutputStream("/tmp/principal.der");
			output.write(cert.getSubjectX500Principal().getEncoded());
			output.close();

			assertEquals("Round-trip handle validation failed on DN.", BaseHandler.getHostNameFromDN(cert
					.getSubjectX500Principal()), "asd3.ais.ucla.edu");

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
		} catch (Exception e) {
			fail("Error in test specification: " + e.getMessage());
		}
	}

}