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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.opensaml.Configuration;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * Validation suite for the <code>RelyingPartyMapper</code>.
 * 
 * @author Walter Hoehn
 */

public class RelyingPartyMapperTests extends TestCase {

	public RelyingPartyMapperTests(String name) {

		super(name);
		BasicConfigurator.resetConfiguration();
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	public static void main(String[] args) {

		junit.textui.TestRunner.run(RelyingPartyMapperTests.class);
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	protected void setUp() throws Exception {

		super.setUp();
	}

	public void testBasicFunction() {

		try {
			// Parse IdP config file
			String fileLocation = "data/relyingPartyMapper1.xml";
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);

			// We have to get a credentials set in order to init the mapper
			NodeList credentialNodes = factory.newDocumentBuilder().parse(
					new InputSource(new FileInputStream(fileLocation))).getDocumentElement().getElementsByTagNameNS(
					Credentials.credentialsNamespace, "Credentials");
			Credentials credentials = new Credentials((Element) credentialNodes.item(0));

			RelyingPartyMapper mapper = new RelyingPartyMapper(factory.newDocumentBuilder().parse(
					new InputSource(new FileInputStream(fileLocation))).getDocumentElement(), credentials);

			// Make sure we have anonymous support turned off
			assertFalse("Anonymous relying party support should be turned off.", mapper.anonymousSuported());

			// Make sure we have defaulting turned off
			assertNull("Expected no relying party.", mapper.getRelyingParty("foobar"));

			// Make sure we can lookup by providerId
			assertNotNull("Expected relying party lookup to succeed.", mapper.getRelyingParty("urn-x:test:1"));

			// Check the config data for the relying party
			assertEquals("Incorrect providerId for relying party.", "urn-x:test:id1", mapper.getRelyingParty(
					"urn-x:test:1").getIdentityProvider().getProviderId());
			assertTrue("Incorrect passThruErrors value for relying party.", mapper.getRelyingParty("urn-x:test:1")
					.passThruErrors());
			assertNotNull("Missing signing credential for relying party.", mapper.getRelyingParty("urn-x:test:1")
					.getIdentityProvider().getSigningCredential());

		} catch (SAXException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (IOException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (RelyingPartyMapperException e) {
			fail("Unable to load relying party mapper: " + e.getMessage());
		} catch (ParserConfigurationException e) {
			fail("Unable to load XML parser: " + e.getMessage());
		}
	}

	public void testAnonymousRelyingParty() {

		try {
			// Parse IdP config file
			String fileLocation = "data/relyingPartyMapper2.xml";
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);

			// We have to get a credentials set in order to init the mapper
			NodeList credentialNodes = factory.newDocumentBuilder().parse(
					new InputSource(new FileInputStream(fileLocation))).getDocumentElement().getElementsByTagNameNS(
					Credentials.credentialsNamespace, "Credentials");
			Credentials credentials = new Credentials((Element) credentialNodes.item(0));

			RelyingPartyMapper mapper = new RelyingPartyMapper(factory.newDocumentBuilder().parse(
					new InputSource(new FileInputStream(fileLocation))).getDocumentElement(), credentials);

			// Make sure we have anonymous support turned on
			assertTrue("Anonymous relying party support should be turned on.", mapper.anonymousSuported());
			assertNotNull("Unable to lookup anonymous relying party.", mapper.getAnonymousRelyingParty());

			// Make sure we got the correct relying party
			assertEquals("Wrong providerId.", "urn-x:test:anonId", mapper.getAnonymousRelyingParty()
					.getIdentityProvider().getProviderId());

		} catch (SAXException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (IOException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (RelyingPartyMapperException e) {
			fail("Unable to load relying party mapper: " + e.getMessage());
		} catch (ParserConfigurationException e) {
			fail("Unable to load XML parser: " + e.getMessage());
		}
	}

	public void testDefaultRelyingParty() {

		try {
			// Parse IdP config file
			String fileLocation = "data/relyingPartyMapper2.xml";
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);

			// We have to get a credentials set in order to init the mapper
			NodeList credentialNodes = factory.newDocumentBuilder().parse(
					new InputSource(new FileInputStream(fileLocation))).getDocumentElement().getElementsByTagNameNS(
					Credentials.credentialsNamespace, "Credentials");
			Credentials credentials = new Credentials((Element) credentialNodes.item(0));

			RelyingPartyMapper mapper = new RelyingPartyMapper(factory.newDocumentBuilder().parse(
					new InputSource(new FileInputStream(fileLocation))).getDocumentElement(), credentials);

			// Make sure we have defaulting turned on
			assertNotNull("Expected no relying party.", mapper.getRelyingParty("foobar"));

			// Make sure we got the correct relying party
			assertEquals("Wrong providerId.", "urn-x:test:defId", mapper.getRelyingParty("foobar")
					.getIdentityProvider().getProviderId());

		} catch (SAXException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (IOException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (RelyingPartyMapperException e) {
			fail("Unable to load relying party mapper: " + e.getMessage());
		} catch (ParserConfigurationException e) {
			fail("Unable to load XML parser: " + e.getMessage());
		}
	}

	public void testGroupLookup() {

		try {
			// Parse IdP config file
			String fileLocation = "data/relyingPartyMapper2.xml";
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);

			// We have to get a credentials set in order to init the mapper
			NodeList credentialNodes = factory.newDocumentBuilder().parse(
					new InputSource(new FileInputStream(fileLocation))).getDocumentElement().getElementsByTagNameNS(
					Credentials.credentialsNamespace, "Credentials");
			Credentials credentials = new Credentials((Element) credentialNodes.item(0));

			RelyingPartyMapper mapper = new RelyingPartyMapper(factory.newDocumentBuilder().parse(
					new InputSource(new FileInputStream(fileLocation))).getDocumentElement(), credentials);

			Configuration.init();
			MetadataProvider metadata = new FilesystemMetadataProvider(new File("data/relyingParty-metadata.xml"));
			mapper.setMetadata(metadata);

			// Make sure we can lookup by group
			assertNotNull("Expected relying party lookup by group to succeed.", mapper.getRelyingParty("urn-x:test:1"));
			assertEquals("Expected relying party lookup by group to have correct providerId.", "urn-x:test:id1", mapper
					.getRelyingParty("urn-x:test:1").getIdentityProvider().getProviderId());

		} catch (SAXException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (IOException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (RelyingPartyMapperException e) {
			fail("Unable to load relying party mapper: " + e.getMessage());
		} catch (MetadataProviderException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (ParserConfigurationException e) {
			fail("Unable to load XML parser: " + e.getMessage());
		}
	}
}