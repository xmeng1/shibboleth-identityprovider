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

package edu.internet2.middleware.shibboleth.aa.arp;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;
import org.xml.sax.InputSource;

import edu.internet2.middleware.shibboleth.aa.AAAttribute;
import edu.internet2.middleware.shibboleth.common.LocalPrincipal;
import edu.internet2.middleware.shibboleth.idp.IdPConfig;
import edu.internet2.middleware.shibboleth.xml.Parser;

/**
 * Validation suite for <code>Arp</code> processing.
 * 
 * @author Walter Hoehn(wassa@memphis.edu)
 */

public class ArpTests extends TestCase {

	private Parser.DOMParser parser = new Parser.DOMParser(true);
	Element memoryRepositoryElement;
	private String[] arpExamples = {"data/example1.xml", "data/example2.xml", "data/example3.xml", "data/example4.xml",
			"data/example5.xml", "data/example6.xml", "data/example7.xml", "data/example8.xml", "data/example9.xml",
			"data/example10.xml", "data/example11.xml", "data/example12.xml", "data/example13.xml"};

	public ArpTests(String name) {

		super(name);
		BasicConfigurator.resetConfiguration();
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	public static void main(String[] args) {

		junit.textui.TestRunner.run(ArpTests.class);
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	/**
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {

		super.setUp();

		// Setup an xml parser

		// Setup a dummy xml config for a Memory-based repository
		DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
		docFactory.setNamespaceAware(true);
		Document placeHolder;
		try {
			placeHolder = docFactory.newDocumentBuilder().newDocument();

			memoryRepositoryElement = placeHolder.createElementNS(IdPConfig.configNameSpace, "ArpRepository");
			memoryRepositoryElement.setAttributeNS(IdPConfig.configNameSpace, "implementation",
					"edu.internet2.middleware.shibboleth.aa.arp.provider.MemoryArpRepository");
		} catch (ParserConfigurationException e) {
			fail("Failed to create memory-based Arp Repository configuration" + e);
		}
	}

	public void testArpMarshalling() {

		// Test ARP description
		try {
			InputStream inStream = new FileInputStream("data/arp1.xml");
			parser.parse(new InputSource(inStream));
			Arp arp1 = new Arp();
			arp1.marshall(parser.getDocument().getDocumentElement());
			assertEquals("ARP Description not marshalled properly", arp1.getDescription(), "Simplest possible ARP.");

			// Test Rule description
			assertEquals("ARP Rule Description not marshalled properly", arp1.getAllRules().iterator().next()
					.getDescription(), "Example Rule Description.");
		} catch (Exception e) {
			fail("Failed to marshall ARP: " + e);
		}

		// Test case where ARP description does not exist
		try {
			InputStream inStream = new FileInputStream("data/arp2.xml");
			parser.parse(new InputSource(inStream));
			Arp arp2 = new Arp();
			arp2.marshall(parser.getDocument().getDocumentElement());
			assertNull("ARP Description not marshalled properly", arp2.getDescription());

			// Test case where ARP Rule description does not exist
			assertNull("ARP Rule Description not marshalled properly", arp2.getAllRules().iterator().next()
					.getDescription());
		} catch (Exception e) {
			fail("Failed to marshall ARP.");
		}

	}

	public void testMatchingFunctions() {

		try {

			/*
			 * Test Arp Engine function retrieval
			 */

			// Lookup a function that doesn't exist
			MatchFunction noFunction = ArpEngine.lookupMatchFunction(new URI(
					"urn:mace:shibboleth:arp:matchFunction:dummy"));
			assertNull("ArpEngine did not return null on dummy function.", noFunction);

			// Lookup some real functions
			MatchFunction stringMatch = ArpEngine.lookupMatchFunction(new URI(
					"urn:mace:shibboleth:arp:matchFunction:stringMatch"));
			assertNotNull("ArpEngine did not properly load the String Match function.", stringMatch);

			MatchFunction regexFunction = ArpEngine.lookupMatchFunction(new URI(
					"urn:mace:shibboleth:arp:matchFunction:regexMatch"));
			assertNotNull("ArpEngine did not properly load the Regex function.", regexFunction);

			MatchFunction regexNotFunction = ArpEngine.lookupMatchFunction(new URI(
					"urn:mace:shibboleth:arp:matchFunction:regexNotMatch"));
			assertNotNull("ArpEngine did not properly load the Regex Not Match function.", regexNotFunction);

			MatchFunction stringNotFunction = ArpEngine.lookupMatchFunction(new URI(
					"urn:mace:shibboleth:arp:matchFunction:stringNotMatch"));
			assertNotNull("ArpEngine did not properly load the String Not Match function.", stringNotFunction);

			/*
			 * Test the Regex function (requester & resource)
			 */

			// Try requester regexes
			assertTrue("Regex function: false negative", regexFunction.match("^shar\\.example\\.edu$",
					"shar.example.edu"));
			assertTrue("Regex function: false negative", regexFunction
					.match("^.*\\.example\\.edu$", "shar.example.edu"));
			assertTrue("Regex function: false negative", regexFunction.match("^shar[1-9]?\\.example\\.edu$",
					"shar1.example.edu"));
			assertTrue("Regex function: false negative", regexFunction.match(".*\\.edu", "shar.example.edu"));
			assertTrue("Regex function: false positive", !regexFunction.match("^shar[1-9]\\.example\\.edu$",
					"shar.example.edu"));
			assertTrue("Regex function: false positive", !regexFunction.match("^shar\\.example\\.edu$",
					"www.example.edu"));
			assertTrue("Regex function: false positive", !regexFunction.match("^shar\\.example\\.edu$",
					"www.example.com"));

			// Make sure we properly handle bad input
			try {
				regexFunction.match(null, null);
				fail("Regex function seems to take improper input without throwing an exception.");
			} catch (ArpException ie) {
				// This is supposed to fail
			}

			// Test the StringNotMatch function
			assertFalse("StringNotMatch function: false positive", stringNotFunction.match("foo", "foo"));
			assertTrue("StringNotMatch function: false negative", stringNotFunction.match("foo", "bar"));
			// Make sure we properly handle bad input
			try {
				stringNotFunction.match(null, null);
				fail("StringNotMatch function seems to take improper input without throwing an exception.");
			} catch (ArpException ie) {
				// This is supposed to fail
			}

			// Test the RegexNotMatch function

			assertFalse("Regex function: false positive", regexNotFunction.match("^foo$", "foo"));
			assertTrue("Regex function: false negative", regexNotFunction.match("foo$", "bar"));

			// Make sure we properly handle bad input
			try {
				regexNotFunction.match(null, null);
				fail("RegexNotMatch function seems to take improper input without throwing an exception.");
			} catch (ArpException ie) {
				// This is supposed to fail
			}

		} catch (ArpException e) {
			fail("Encountered a problem loading match function: " + e);
		} catch (URISyntaxException e) {
			fail("Unable to create URI from test string.");
		}

	}

	public void testRepositories() {

		/*
		 * Test the Factory
		 */

		// Make sure we fail if an unavailable Repository implementation is specified
		ArpRepository repository = null;

		DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
		docFactory.setNamespaceAware(true);
		Document placeHolder;
		try {
			placeHolder = docFactory.newDocumentBuilder().newDocument();

			Element repositoryElement = placeHolder.createElementNS(IdPConfig.configNameSpace, "ArpRepository");
			repositoryElement.setAttributeNS(IdPConfig.configNameSpace, "implementation",
					"edu.internet2.middleware.shibboleth.aa.arp.provider.Foo");

			ArpRepositoryFactory.getInstance(repositoryElement);

		} catch (ParserConfigurationException e) {
			fail("Failed to create bogus Arp Repository configuration" + e);

		} catch (ArpRepositoryException e) {
			// This is supposed to fail
		}

		// Make sure we can create an Arp Repository
		repository = null;
		try {
			repository = ArpRepositoryFactory.getInstance(memoryRepositoryElement);
		} catch (ArpRepositoryException e) {
			fail("Failed to create memory-based Arp Repository" + e);
		}
		assertNotNull("Failed to create memory-based Arp Repository: Factory returned null.", repository);

		/*
		 * Exercise the Memory Arp Repository
		 */

		// Set/retrieve/remove a Site ARP
		Arp siteArp1 = new Arp();
		siteArp1.setDescription("Test Site Arp 1.");
		try {
			repository.update(siteArp1);
			assertEquals("Memory Repository does not store and retrieve Site ARPs properly.", siteArp1, repository
					.getSitePolicy());
			repository.remove(repository.getSitePolicy());
			assertNull("Memorty Repository does not properly delete Site ARPs.", repository.getSitePolicy());
		} catch (ArpRepositoryException e) {
			fail("Error adding Site ARP to Memory Repository.");
		}

		// Set/retrieve/delete some user ARPs
		Arp userArp1 = new Arp();
		userArp1.setDescription("Broken User Arp 1.");
		try {
			repository.update(userArp1);
			assertTrue("Memory Repository does not store and retrieve User ARPs properly.", (!userArp1
					.equals(repository.getUserPolicy(userArp1.getPrincipal()))));
		} catch (ArpRepositoryException e) {
			fail("Error adding User ARP to Memory Repository.");
		}

		Arp userArp2 = new Arp(new LocalPrincipal("TestPrincipal"));
		userArp2.setDescription("Test User Arp 2.");
		try {
			repository.update(userArp2);
			assertEquals("Memory Repository does not store and retrieve User ARPs properly.", userArp2, repository
					.getUserPolicy(userArp2.getPrincipal()));
			repository.remove(repository.getUserPolicy(userArp2.getPrincipal()));
			assertNull("Memorty Repository does not properly delete User ARPs.", repository.getUserPolicy(userArp2
					.getPrincipal()));
		} catch (ArpRepositoryException e) {
			fail("Error adding User ARP to Memory Repository.");
		}

		// create a repository
		repository = null;

		try {
			placeHolder = docFactory.newDocumentBuilder().newDocument();

			Element repositoryElement = placeHolder.createElementNS(IdPConfig.configNameSpace, "ArpRepository");
			repositoryElement.setAttributeNS(IdPConfig.configNameSpace, "implementation",
					"edu.internet2.middleware.shibboleth.aa.arp.provider.FileSystemArpRepository");
			repositoryElement.setAttributeNS(IdPConfig.configNameSpace, "arpTTL", "65535");

			Element path = placeHolder.createElementNS(IdPConfig.configNameSpace, "Path");
			Text text = placeHolder.createTextNode(new File("data/").toURI().toString());
			path.appendChild(text);

			repositoryElement.appendChild(path);

			repository = ArpRepositoryFactory.getInstance(repositoryElement);

		} catch (ArpRepositoryException e) {
			fail("Failed to create file-based Arp Repository" + e);
		} catch (ParserConfigurationException e) {
			fail("Failed to create file-based Arp Repository configuration" + e);
		}

		assertNotNull("Failed to create file-based Arp Repository: Factory returned null.", repository);

		try {
			Arp siteArp = repository.getSitePolicy();

			InputStream inStream = new FileInputStream("data/arp.site.xml");
			parser.parse(new InputSource(inStream));
			String directXML = Parser.serialize(parser.getDocument().getDocumentElement());

			String processedXML = Parser.serialize(siteArp.unmarshall());

			assertTrue("File-based ARP Repository did not return the correct site ARP.", directXML.toString()
					.replaceAll(">[\t\r\n ]+<", "><").equals(processedXML.toString().replaceAll(">[\t\r\n ]+<", "><")));

			Arp userArp = repository.getUserPolicy(new LocalPrincipal("test"));

			inStream = new FileInputStream("data/arp.user.test.xml");
			parser.parse(new InputSource(inStream));
			directXML = Parser.serialize(parser.getDocument().getDocumentElement());

			processedXML = Parser.serialize(userArp.unmarshall());

			assertTrue("File-based ARP Repository did not return the correct user ARP.", directXML.toString()
					.replaceAll(">[\t\r\n ]+<", "><").equals(processedXML.toString().replaceAll(">[\t\r\n ]+<", "><")));

			Arp[] allArps = repository.getAllPolicies(new LocalPrincipal("test"));

			assertTrue("File-based ARP Repository did not return the correct number of ARPs.", (allArps.length == 2));

		} catch (Exception e) {
			fail("Error retrieving ARP from Repository: " + e);
		}

	}

	public void testPossibleReleaseSetComputation() {

		ArpRepository repository = null;
		try {
			repository = ArpRepositoryFactory.getInstance(memoryRepositoryElement);
		} catch (ArpRepositoryException e) {
			fail("Failed to create memory-based Arp Repository" + e);
		}

		try {
			Principal principal1 = new LocalPrincipal("TestPrincipal");

			Set<URI> list1 = new HashSet<URI>();
			list1.add(new URI("urn:mace:dir:attribute-def:eduPersonAffiliation"));

			Set<URI> list2 = new HashSet<URI>();
			list2.add(new URI("urn:mace:dir:attribute-def:eduPersonAffiliation"));
			list2.add(new URI("urn:mace:dir:attribute-def:eduPersonPrincipalName"));

			Set<URI> list3 = new HashSet<URI>();

			// Test with just a site ARP
			InputStream inStream = new FileInputStream("data/arp1.xml");
			parser.parse(new InputSource(inStream));
			Arp arp1 = new Arp();
			arp1.marshall(parser.getDocument().getDocumentElement());
			repository.update(arp1);
			ArpEngine engine = new ArpEngine(repository);
			Set<URI> possibleAttributes = engine.listPossibleReleaseAttributes(principal1, "shar.example.edu");
			assertEquals("Incorrectly computed possible release set (1).", possibleAttributes, list1);

			// Test with site and user ARPs
			inStream = new FileInputStream("data/arp7.xml");
			parser.parse(new InputSource(inStream));
			Arp arp7 = new Arp();
			arp7.setPrincipal(principal1);
			arp7.marshall(parser.getDocument().getDocumentElement());
			repository.update(arp7);
			possibleAttributes = engine.listPossibleReleaseAttributes(principal1, "shar.example.edu");
			assertEquals("Incorrectly computed possible release set (2).", possibleAttributes, list2);

			// Ensure that explicit denies on any value are not in the release set
			inStream = new FileInputStream("data/arp6.xml");
			parser.parse(new InputSource(inStream));
			Arp arp6 = new Arp();
			arp6.setPrincipal(principal1);
			arp6.marshall(parser.getDocument().getDocumentElement());
			repository.update(arp6);
			possibleAttributes = engine.listPossibleReleaseAttributes(principal1, "shar.example.edu");
			assertEquals("Incorrectly computed possible release set (3).", possibleAttributes, list3);

		} catch (Exception e) {
			e.printStackTrace();
			fail("Failed to marshall ARP: " + e);
		}

	}

	public void testArpApplication() {

		// Construct an engine with a memory-based repository
		ArpRepository repository = null;
		try {
			repository = ArpRepositoryFactory.getInstance(memoryRepositoryElement);

		} catch (ArpRepositoryException e) {
			fail("Failed to create memory-based Arp Repository" + e);
		}

		try {
			
			arpApplicationTest1(repository, parser);
			arpApplicationTest2(repository, parser);
			arpApplicationTest3(repository, parser);
			arpApplicationTest4(repository, parser);
			arpApplicationTest5(repository, parser);
			arpApplicationTest6(repository, parser);
			arpApplicationTest7(repository, parser);
			arpApplicationTest8(repository, parser);
			arpApplicationTest9(repository, parser);
			arpApplicationTest10(repository, parser);
			arpApplicationTest11(repository, parser);
			arpApplicationTest12(repository, parser);
			arpApplicationTest13(repository, parser);
			arpApplicationTest14(repository, parser);
			arpApplicationTest15(repository, parser);
			arpApplicationTest17(repository, parser);
			arpApplicationTest18(repository, parser);
			arpApplicationTest19(repository, parser);
			arpApplicationTest20(repository, parser);
			arpApplicationTest21(repository, parser);
			arpApplicationTest22(repository, parser);
			arpApplicationTest23(repository, parser);
			arpApplicationTest24(repository, parser);
			 
		} catch (Exception e) {
			e.printStackTrace();
			fail("Failed to apply filter to ARPs: " + e);
		}
	}

	public void testRoundtripMarshalling() {

		try {
			for (int i = 0; i < arpExamples.length; i++) {

				// Get a non-validating parser so we don't fill in schema defaults
				Parser.DOMParser nonValParser = new Parser.DOMParser(false);

				InputStream inStream = new FileInputStream(arpExamples[i]);

				nonValParser.parse(new InputSource(inStream));
				String directXML = Parser.serialize(nonValParser.getDocument().getDocumentElement());
				inStream.close();

				// Use validation when marshalling into an ARP
				inStream = new FileInputStream(arpExamples[i]);
				parser.parse(new InputSource(inStream));
				Arp arp1 = new Arp();
				arp1.marshall(parser.getDocument().getDocumentElement());
				String processedXML = Parser.serialize(arp1.unmarshall());

				assertEquals("Round trip marshall/unmarshall failed for file (" + arpExamples[i] + ")", directXML
						.toString().replaceAll(">[\t\r\n ]+<", "><"), processedXML.toString().replaceAll(
						">[\t\r\n ]+<", "><"));
			}

		} catch (Exception e) {
			e.printStackTrace();
			fail("Failed to marshall ARP: " + e);
		}

	}
	/**
	 * ARPs: A site ARP only Target: Single Attribute: Any value release.  Most basic test.
	 */
	void arpApplicationTest1(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		// Gather the Input
		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>" 
				+ "				<Target>" 
				+ "					<AnyTarget/>" 
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>" 
				+ "				</Attribute>" 
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new LocalPrincipal("TestPrincipal");
		
		Collection<AAAttribute> inputSet = new ArrayList<AAAttribute>(Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu"})));

		Collection<AAAttribute> releaseSet = Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu"}));

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		// Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu");

		assertEquals("ARP application test 1: ARP not applied as expected.", inputSet, releaseSet);
	}


	/**
	 * ARPs: A site ARP only Target: Single Attribute: Any value release.  Test implicit deny of other attributes.
	 */
	void arpApplicationTest2(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		// Gather the Input
		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>" 
				+ "				<Target>" 
				+ "					<AnyTarget/>" 
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>" 
				+ "				</Attribute>" 
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new LocalPrincipal("TestPrincipal");
		Collection<AAAttribute> inputSet = new ArrayList<AAAttribute>(Arrays.asList(new AAAttribute[]{
				new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu"}),
				new AAAttribute("urn:mace:dir:attribute-def:eduPersonPrincipalName",
						new Object[]{"mehoehn@example.edu"})}));

		Collection<AAAttribute> releaseSet = Arrays.asList(new AAAttribute[]{new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu"})});

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		// Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu");

		assertEquals("ARP application test 2: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP only Target: Single Attribute: Single value release
	 */
	void arpApplicationTest3(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		// Gather the Input
		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>" 
				+ "				<Target>" 
				+ "					<AnyTarget/>" 
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<Value release=\"permit\">member@example.edu</Value>" 
				+ "				</Attribute>" 
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new LocalPrincipal("TestPrincipal");
		Collection<AAAttribute> inputSet = new ArrayList<AAAttribute>(Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu"})));
		Collection<AAAttribute> releaseSet = Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu"}));

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		// Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu");

		assertEquals("ARP application test 3: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP only Target: Single Attribute: Any value except one release, canonical representation
	 */
	void arpApplicationTest4(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		// Gather the Input
		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>" 
				+ "					<AnyTarget/>" 
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>" 
				+ "					<Value release=\"deny\">member@example.edu</Value>"
				+ "				</Attribute>" 
				+ "			</Rule>" 
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new LocalPrincipal("TestPrincipal");
		
		Collection<AAAttribute> inputSet = new ArrayList<AAAttribute>(Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu", "employee@example.edu"})));
		Collection<AAAttribute> releaseSet = Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"faculty@example.edu",
						"employee@example.edu"}));

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		// Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu");

		assertEquals("ARP application test 4: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP any Target: Single Attribute: Any value except one release, expanded representation
	 */
	void arpApplicationTest5(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		// Gather the Input
		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>" 
				+ "				<Target>" 
				+ "					<AnyTarget/>" 
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>" 
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<Value release=\"deny\">member@example.edu</Value>" 
				+ "				</Attribute>" 
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new LocalPrincipal("TestPrincipal");
	
		Collection<AAAttribute> inputSet = new ArrayList<AAAttribute>(Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu", "employee@example.edu"})));
		Collection<AAAttribute> releaseSet = Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"faculty@example.edu",
						"employee@example.edu"}));

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		// Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu");

		assertEquals("ARP application test 5: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP any Target: Single Attribute: Any value except two release, expanded representation
	 */
	void arpApplicationTest6(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		// Gather the Input
		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>" 
				+ "				<Target>" 
				+ "					<AnyTarget/>" 
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>" 
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<Value release=\"deny\">member@example.edu</Value>" 
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<Value release=\"deny\">faculty@example.edu</Value>" 
				+ "				</Attribute>" 
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new LocalPrincipal("TestPrincipal");
		
		Collection<AAAttribute> inputSet = new ArrayList<AAAttribute>(Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu", "employee@example.edu"})));
		Collection<AAAttribute> releaseSet = Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"employee@example.edu"}));

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		// Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu");

		assertEquals("ARP application test 6: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP any Target: Single Attribute: Two value release, canonical representation
	 */
	void arpApplicationTest7(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		// Gather the Input
		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>" 
				+ "				<Target>" 
				+ "					<AnyTarget/>" 
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<Value release=\"permit\">member@example.edu</Value>"
				+ "					<Value release=\"permit\">faculty@example.edu</Value>" 
				+ "				</Attribute>" 
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new LocalPrincipal("TestPrincipal");

		Collection<AAAttribute> inputSet = new ArrayList<AAAttribute>(Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu", "employee@example.edu"})));
		Collection<AAAttribute> releaseSet = Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu"}));

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		// Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu");

		assertEquals("ARP application test 3: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP any Target: Single Attribute: Two value release, expanded representation
	 */
	void arpApplicationTest8(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		// Gather the Input
		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>" 
				+ "				<Target>" 
				+ "					<AnyTarget/>" 
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<Value release=\"permit\">member@example.edu</Value>" 
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<Value release=\"permit\">faculty@example.edu</Value>" 
				+ "				</Attribute>" 
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new LocalPrincipal("TestPrincipal");

		Collection<AAAttribute> inputSet = new ArrayList<AAAttribute>(Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu", "employee@example.edu"})));
		Collection<AAAttribute> releaseSet = Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu"}));

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		// Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu");

		assertEquals("ARP application test 8: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP any Target: Single Attribute: Any value deny
	 */
	void arpApplicationTest9(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		// Gather the Input
		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>" 
				+ "				<Target>" 
				+ "					<AnyTarget/>" 
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"deny\"/>" 
				+ "				</Attribute>" 
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new LocalPrincipal("TestPrincipal");

		Collection<AAAttribute> inputSet = new ArrayList<AAAttribute>(Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu"})));

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		// Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu");

		assertEquals("ARP application test 9: ARP not applied as expected.", inputSet, new ArrayList<AAAttribute>());
	}

	/**
	 * ARPs: A site ARP any Target: Single Attribute: Any value deny trumps explicit permit expanded representation
	 */
	void arpApplicationTest10(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		// Gather the Input
		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>" 
				+ "				<Target>" 
				+ "					<AnyTarget/>" 
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"deny\"/>" 
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<Value release=\"permit\">member@example.edu</Value>" 
				+ "				</Attribute>" 
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new LocalPrincipal("TestPrincipal");

		Collection<AAAttribute> inputSet = new ArrayList<AAAttribute>(Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu"})));

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		// Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu");

		assertEquals("ARP application test 10: ARP not applied as expected.", inputSet, new ArrayList<AAAttribute>());
	}
	/**
	 * ARPs: A site ARP any Target: single Attribute: Any value deny trumps explicit permit canonical representation
	 */
	void arpApplicationTest11(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		// Gather the Input
		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>" 
				+ "				<Target>" 
				+ "					<AnyTarget/>" 
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"deny\"/>" 
				+ "					<Value release=\"permit\">member@example.edu</Value>"
				+ "				</Attribute>" 
				+ "			</Rule>" 
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new LocalPrincipal("TestPrincipal");

		Collection<AAAttribute> inputSet = new ArrayList<AAAttribute>(Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu"})));

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		// Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu");

		assertEquals("ARP application test 11: ARP not applied as expected.", inputSet, new ArrayList<AAAttribute>());
	}

	/**
	 * ARPs: Test release to a specific requester
	 */
	void arpApplicationTest12(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		// Gather the Input
		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>" 
				+ "				<Target>" 
				+ "					<Requester>shar.example.edu</Requester>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>" 
				+ "				</Attribute>" 
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new LocalPrincipal("TestPrincipal");

		Collection<AAAttribute> inputSet = new ArrayList<AAAttribute>(Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu"})));
		Collection<AAAttribute> releaseSet = Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu"}));

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		// Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu");

		assertEquals("ARP application test 12: ARP not applied as expected.", inputSet, releaseSet);
	}
	/**
	 * ARPs: Test release to multiple specific requesters
	 */
	void arpApplicationTest13(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		// Gather the Input
		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>" 
				+ "				<Target>" 
				+ "					<Requester>shar.example.edu</Requester>"
				+ "					<Requester>http://foo.example.edu</Requester>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>" 
				+ "				</Attribute>" 
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new LocalPrincipal("TestPrincipal");

		Collection<AAAttribute> inputSet = new ArrayList<AAAttribute>(Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu"})));
		Collection<AAAttribute> releaseSet = Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu"}));

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		// Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu");

		assertEquals("ARP application test 12: ARP not applied as expected.", inputSet, releaseSet);
		
		// Try for the 2nd requester
		inputSet = new ArrayList<AAAttribute>(Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu"})));
		
		engine.filterAttributes(inputSet, principal1, "http://foo.example.edu");
		assertEquals("ARP application test 12: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: Specific requester (no match)
	 */
	void arpApplicationTest14(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		// Gather the Input
		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>" 
				+ "				<Target>" 
				+ "					<Requester>shar.example.edu</Requester>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>" 
				+ "				</Attribute>" 
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new LocalPrincipal("TestPrincipal");

		Collection<AAAttribute> inputSet = new ArrayList<AAAttribute>(Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu"})));

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		// Apply the ARP
		engine.filterAttributes(inputSet, principal1, "www.example.edu");

		assertEquals("ARP application test 14: ARP not applied as expected.", inputSet, new ArrayList<AAAttribute>());
	}
	/**
	 * ARPs: Multiple specific requesters (no match)
	 */
	void arpApplicationTest15(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		// Gather the Input
		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>" 
				+ "				<Target>" 
				+ "					<Requester>shar.example.edu</Requester>"
				+ "					<Requester>http://foo.example.edu</Requester>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>" 
				+ "				</Attribute>" 
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new LocalPrincipal("TestPrincipal");

		Collection<AAAttribute> inputSet = new ArrayList<AAAttribute>(Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu"})));

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		// Apply the ARP
		engine.filterAttributes(inputSet, principal1, "www.example.edu");

		assertEquals("ARP application test 14: ARP not applied as expected.", inputSet, new ArrayList<AAAttribute>());
	}

	/**
	 * ARPs: A site ARP only Target: Multiple matching rules Attribute: various
	 */
	void arpApplicationTest17(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		// Gather the Input
		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<AnyTarget />"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<Requester>shar1.example.edu</Requester>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<Value release=\"deny\">faculty@example.edu</Value>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<Requester matchFunction=\"urn:mace:shibboleth:arp:matchFunction:regexMatch\">shar[1-9]\\.example\\.edu</Requester>"
				+ "				</Target>" 
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonPrincipalName\">"
				+ "					<AnyValue release=\"permit\"/>" 
				+ "				</Attribute>" 
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new LocalPrincipal("TestPrincipal");
		Collection<AAAttribute> inputSet = new ArrayList<AAAttribute>(Arrays
				.asList(new AAAttribute[]{
						new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{
								"member@example.edu", "faculty@example.edu"}),
						new AAAttribute("urn:mace:dir:attribute-def:eduPersonPrincipalName",
								new Object[]{"wassa@columbia.edu"})}));

		Collection<AAAttribute> releaseSet = Arrays
				.asList(new AAAttribute[]{
						new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation",
								new Object[]{"member@example.edu"}),
						new AAAttribute("urn:mace:dir:attribute-def:eduPersonPrincipalName",
								new Object[]{"wassa@columbia.edu"})});

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		// Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar1.example.edu");

		assertEquals("ARP application test 17: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP any Target: Any Attribute: Any value release of two attributes in one rule
	 */
	void arpApplicationTest18(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		// Gather the Input
		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>" 
				+ "				<Target>" 
				+ "					<AnyTarget/>" 
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>" 
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonPrincipalName\">"
				+ "					<AnyValue release=\"permit\"/>" 
				+ "				</Attribute>" 
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new LocalPrincipal("TestPrincipal");

		Collection<AAAttribute> inputSet = new ArrayList<AAAttribute>(Arrays.asList(new AAAttribute[]{
				new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu"}),
				new AAAttribute("urn:mace:dir:attribute-def:eduPersonPrincipalName",
						new Object[]{"mehoehn@example.edu"})}));

		Collection<AAAttribute> releaseSet = Arrays.asList(new AAAttribute[]{
				new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu"}),
				new AAAttribute("urn:mace:dir:attribute-def:eduPersonPrincipalName",
						new Object[]{"mehoehn@example.edu"})});

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		// Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu");

		assertEquals("ARP application test 18: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A user ARP any Target: Single Attribute: Any value release,
	 */
	void arpApplicationTest19(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		// Gather the Input
		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>" 
				+ "				<Target>" 
				+ "					<AnyTarget/>" 
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>" 
				+ "				</Attribute>" 
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new LocalPrincipal("TestPrincipal");

		Collection<AAAttribute> inputSet = new ArrayList<AAAttribute>(Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu"})));
		Collection<AAAttribute> releaseSet = Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu",
						"faculty@example.edu"}));

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp userArp = new Arp();
		userArp.setPrincipal(principal1);
		userArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(userArp);
		ArpEngine engine = new ArpEngine(repository);

		// Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu");

		assertEquals("ARP application test 19: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP and user ARP Target: various Attribute: various combinations
	 */
	void arpApplicationTest20(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		// Gather the Input
		String rawSiteArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<AnyTarget/>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<Value release=\"permit\">member@example.edu</Value>"
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:inetOrgPerson:preferredLanguage\">"
				+ "					<AnyValue release=\"permit\" />"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<Requester matchFunction=\"urn:mace:shibboleth:arp:matchFunction:regexMatch\">.*\\.example\\.edu</Requester>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonPrincipalName\">"
				+ "					<AnyValue release=\"permit\"/>" 
				+ "				</Attribute>" 
				+ "			</Rule>" 
				+ "			<Rule>"
				+ "				<Target>" 
				+ "					<Requester>www.example.edu</Requester>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>" 
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonEntitlement\">"
				+ "					<Value release=\"permit\">urn:example:contract:4657483</Value>" 
				+ "				</Attribute>"
				+ "			</Rule>" 
				+ "			<Rule>" 
				+ "				<Target>" 
				+ "					<Requester>www.external.com</Requester>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonEntitlement\">"
				+ "					<Value release=\"permit\">urn:example:contract:113455</Value>" 
				+ "				</Attribute>"
				+ "			</Rule>" 
				+ "	</AttributeReleasePolicy>";

		String rawUserArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<AnyTarget/>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonEntitlement\">"
				+ "					<Value release=\"deny\">urn:example:poorlyDressed</Value>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<Requester matchFunction=\"urn:mace:shibboleth:arp:matchFunction:regexMatch\">.*\\.example\\.edu</Requester>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<Value release=\"deny\">faculty@example.edu</Value>" 
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonEntitlement\">"
				+ "					<Value release=\"permit\">urn:example:lovesIceCream</Value>" 
				+ "				</Attribute>"
				+ "			</Rule>" 
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new LocalPrincipal("TestPrincipal");

		Collection<AAAttribute> inputSet = new ArrayList<AAAttribute>(Arrays
				.asList(new AAAttribute[]{
						new AAAttribute("urn:mace:dir:attribute-def:eduPersonEntitlement", new Object[]{
								"urn:example:lovesIceCream", "urn:example:poorlyDressed",
								"urn:example:contract:113455", "urn:example:contract:4657483"}),
						new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{
								"member@example.edu", "faculty@example.edu", "employee@example.edu"}),
						new AAAttribute("urn:mace:dir:attribute-def:eduPersonPrincipalName",
								new Object[]{"wassa@example.edu"}),
						new AAAttribute("urn:mace:inetOrgPerson:preferredLanguage", new Object[]{"EO"})}));

		Collection<AAAttribute> releaseSet = Arrays
				.asList(new AAAttribute[]{
						new AAAttribute("urn:mace:dir:attribute-def:eduPersonEntitlement", new Object[]{
								"urn:example:lovesIceCream", "urn:example:contract:4657483"}),
						new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{
								"member@example.edu", "employee@example.edu"}),
						new AAAttribute("urn:mace:dir:attribute-def:eduPersonPrincipalName",
								new Object[]{"wassa@example.edu"}),
						new AAAttribute("urn:mace:inetOrgPerson:preferredLanguage", new Object[]{"EO"})});

		// Add the site ARP
		parser.parse(new InputSource(new StringReader(rawSiteArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);

		// Add the user ARP
		parser.parse(new InputSource(new StringReader(rawUserArp)));
		Arp userArp = new Arp();
		userArp.setPrincipal(principal1);
		userArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(userArp);

		ArpEngine engine = new ArpEngine(repository);

		// Apply the ARP
		engine.filterAttributes(inputSet, principal1, "www.example.edu");

		assertEquals("ARP application test 20: ARP not applied as expected.", inputSet, releaseSet);
	}
	/**
	 * ARPs: A site ARP and user ARP Target: various Attribute: various combinations (same ARPs as 20, different
	 * requester)
	 */
	void arpApplicationTest21(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		// Gather the Input
		String rawSiteArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<AnyTarget/>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<Value release=\"permit\">member@example.edu</Value>"
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:inetOrgPerson:preferredLanguage\">"
				+ "					<AnyValue release=\"permit\" />"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<Requester matchFunction=\"urn:mace:shibboleth:arp:matchFunction:regexMatch\">.*\\.example\\.edu</Requester>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonPrincipalName\">"
				+ "					<AnyValue release=\"permit\"/>" 
				+ "				</Attribute>" 
				+ "			</Rule>" 
				+ "			<Rule>"
				+ "				<Target>" 
				+ "					<Requester>www.example.edu</Requester>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>" 
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonEntitlement\">"
				+ "					<Value release=\"permit\">urn:example:contract:4657483</Value>" 
				+ "				</Attribute>"
				+ "			</Rule>" 
				+ "			<Rule>" 
				+ "				<Target>" 
				+ "					<Requester>www.external.com</Requester>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonEntitlement\">"
				+ "					<Value release=\"permit\">urn:example:contract:113455</Value>" 
				+ "				</Attribute>"
				+ "			</Rule>" 
				+ "	</AttributeReleasePolicy>";

		String rawUserArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<AnyTarget/>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonEntitlement\">"
				+ "					<Value release=\"deny\">urn:example:poorlyDressed</Value>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<Requester matchFunction=\"urn:mace:shibboleth:arp:matchFunction:regexMatch\">.*\\.example\\.edu</Requester>" 
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<Value release=\"deny\">faculty@example.edu</Value>" 
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonEntitlement\">"
				+ "					<Value release=\"permit\">urn:example:lovesIceCream</Value>" 
				+ "				</Attribute>"
				+ "			</Rule>" 
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new LocalPrincipal("TestPrincipal");

		Collection<AAAttribute> inputSet = new ArrayList<AAAttribute>(Arrays
				.asList(new AAAttribute[]{
						new AAAttribute("urn:mace:dir:attribute-def:eduPersonEntitlement", new Object[]{
								"urn:example:lovesIceCream", "urn:example:poorlyDressed",
								"urn:example:contract:113455", "urn:example:contract:4657483"}),
						new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{
								"member@example.edu", "faculty@example.edu", "employee@example.edu"}),
						new AAAttribute("urn:mace:dir:attribute-def:eduPersonPrincipalName",
								new Object[]{"wassa@example.edu"}),
						new AAAttribute("urn:mace:inetOrgPerson:preferredLanguage", new Object[]{"EO"})}));

		Collection<AAAttribute> releaseSet = Arrays.asList(new AAAttribute[]{
				new AAAttribute("urn:mace:dir:attribute-def:eduPersonEntitlement",
						new Object[]{"urn:example:contract:113455"}),
				new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member@example.edu"}),
				new AAAttribute("urn:mace:inetOrgPerson:preferredLanguage", new Object[]{"EO"})});

		// Add the site ARP
		parser.parse(new InputSource(new StringReader(rawSiteArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);

		// Add the user ARP
		parser.parse(new InputSource(new StringReader(rawUserArp)));
		Arp userArp = new Arp();
		userArp.setPrincipal(principal1);
		userArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(userArp);

		ArpEngine engine = new ArpEngine(repository);

		// Apply the ARP
		engine.filterAttributes(inputSet, principal1, "www.external.com");

		assertEquals("ARP application test 21: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP any Target: Specific requester: Release values by regex
	 */
	void arpApplicationTest22(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		// Gather the Input
		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<Requester>shar.example.edu</Requester>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonEntitlement\">"
				+ "					<Value release=\"permit\" matchFunction=\"urn:mace:shibboleth:arp:matchFunction:regexMatch\">^urn:x:a.+$</Value>"
				+ "				</Attribute>"
				+ "			</Rule>" 
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new LocalPrincipal("Test2Principal");

		Collection<AAAttribute> inputSet = new ArrayList<AAAttribute>(Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonEntitlement", new Object[]{"urn:x:a", "urn:x:foo", "urn:x:bar",
						"urn:x:adagio", "urn:x:awol"})));
		Collection<AAAttribute> releaseSet = Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonEntitlement", new Object[]{"urn:x:adagio", "urn:x:awol"}));

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		// Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu");

		assertEquals("ARP application test 22: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP any Target: Specific shar, Attribute: Deny specific values by regex
	 */
	void arpApplicationTest23(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		// Gather the Input
		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<Requester>shar.example.edu</Requester>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonEntitlement\">"
				+ "					<AnyValue release=\"permit\" />"
				+ "					<Value release=\"deny\" matchFunction=\"urn:mace:shibboleth:arp:matchFunction:regexMatch\">^urn:x:a.+$</Value>"
				+ "				</Attribute>" + "			</Rule>" + "	</AttributeReleasePolicy>";

		Principal principal1 = new LocalPrincipal("Test2Principal");

		Collection<AAAttribute> inputSet = new ArrayList<AAAttribute>(Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonEntitlement", new Object[]{"urn:x:a", "urn:x:foo", "urn:x:bar",
						"urn:x:adagio", "urn:x:awol"})));
		Collection<AAAttribute> releaseSet = Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonEntitlement", new Object[]{"urn:x:a", "urn:x:foo", "urn:x:bar"}));

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		// Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu");

		assertEquals("ARP application test 23: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP Specific requester, Attribute: No matches on specific values should
	 * yield no attribute
	 */
	void arpApplicationTest24(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		// Gather the Input
		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>" 
				+ "				<Target>" 
				+ "					<Requester>shar.example.edu</Requester>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\" />" 
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:dir:attribute-def:eduPersonEntitlement\">"
				+ "					<Value release=\"permit\">urn:x:foo</Value>" 
				+ "				</Attribute>" 
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new LocalPrincipal("Test2Principal");

		Collection<AAAttribute> inputSet = new ArrayList<AAAttribute>(Arrays.asList(new AAAttribute[]{
				new AAAttribute("urn:mace:dir:attribute-def:eduPersonEntitlement", new Object[]{"urn:x:bar",
						"urn:x:adagio"}),
				new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member"})}));
		Collection<AAAttribute> releaseSet = Arrays.asList(new AAAttribute(
				"urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member"}));

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		// Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu");

		assertEquals("ARP application test 24: ARP not applied as expected.", inputSet, releaseSet);
	}


	 /**
	 * Use Case: must have an attribute
	 * Example:  release uid only if user has any value for attribute "foo"
	 */
	void arpConstraintTest1(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "         <Rule>" 
				+ "             <Constraint"
				+ "					attributeName=\"urn:mace:dir:attribute-def:foo\""
				+ "					matchFunction=\"urn:mace:shibboleth:arp:matchFunction:anyValueMatch\""
				+ "					matches=\"any\"/>"
				+ "             <Target>" 
				+ "                 <AnyTarget/>" 
				+ "             </Target>"
				+ "             <Attribute name=\"urn:mace:dir:attribute-def:uid\">"
				+ "                 <AnyValue release=\"permit\"/>" 
				+ "             </Attribute>" 
				+ "         </Rule>"
				+ " </AttributeReleasePolicy>";

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		Principal principal = new LocalPrincipal("TestPrincipal");

		// test user who meets constraint
		Collection<AAAttribute> inputSet1 = new ArrayList<AAAttribute>();
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:foo", new Object[]{"bar"}));

		Collection<AAAttribute> releaseSet1 = new ArrayList<AAAttribute>();
		releaseSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		engine.filterAttributes(inputSet1, principal, "shar.example.edu");
		assertEquals("ARP application test 1a: ARP not applied as expected.", releaseSet1, inputSet1);

		// test user who does not meet constraint
		Collection<AAAttribute> inputSet2 = new ArrayList<AAAttribute>();
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		Collection<AAAttribute> releaseSet2 = new ArrayList<AAAttribute>();

		engine.filterAttributes(inputSet2, principal, "shar.example.edu");
		assertEquals("ARP application test 1b: ARP not applied as expected.", releaseSet2, inputSet2);

	}
	
	 /**
	 * Use Case: must have an attribute value
	 * Example:  release uid only if user has a specific value for attribute "foo"
	 */
	void arpConstraintTest2(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "         <Rule>" 
				+ "             <Constraint"
				+ "					attributeName=\"urn:mace:dir:attribute-def:foo\""
				+ "					matchFunction=\"urn:mace:shibboleth:arp:matchFunction:stringValueMatch\""
				+ "					matches=\"any\">bar</Constraint>"
				+ "             <Target>" 
				+ "                 <AnyTarget/>" 
				+ "             </Target>"
				+ "             <Attribute name=\"urn:mace:dir:attribute-def:uid\">"
				+ "                 <AnyValue release=\"permit\"/>" 
				+ "             </Attribute>" 
				+ "         </Rule>"
				+ " </AttributeReleasePolicy>";

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		Principal principal = new LocalPrincipal("TestPrincipal");

		// test user who meets constraint
		Collection<AAAttribute> inputSet1 = new ArrayList<AAAttribute>();
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:foo", new Object[]{"bar"}));

		Collection<AAAttribute> releaseSet1 = new ArrayList<AAAttribute>();
		releaseSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		engine.filterAttributes(inputSet1, principal, "shar.example.edu");
		assertEquals("ARP application test 1a: ARP not applied as expected.", releaseSet1, inputSet1);

		// test user who does not meet constraint
		Collection<AAAttribute> inputSet2 = new ArrayList<AAAttribute>();
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		Collection<AAAttribute> releaseSet2 = new ArrayList<AAAttribute>();

		engine.filterAttributes(inputSet2, principal, "shar.example.edu");
		assertEquals("ARP application test 1b: ARP not applied as expected.", releaseSet2, inputSet2);

	}
	 /**
	 * Use Case: must have only a specific attribute value
	 * Example:  release uid only if user has a specific value for attribute "foo", but not if it has other values
	 */
	void arpConstraintTest3(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "         <Rule>" 
				+ "             <Constraint"
				+ "					attributeName=\"urn:mace:dir:attribute-def:foo\""
				+ "					matchFunction=\"urn:mace:shibboleth:arp:matchFunction:stringValueMatch\""
				+ "					matches=\"all\">bar</Constraint>"
				+ "             <Target>" 
				+ "                 <AnyTarget/>" 
				+ "             </Target>"
				+ "             <Attribute name=\"urn:mace:dir:attribute-def:uid\">"
				+ "                 <AnyValue release=\"permit\"/>" 
				+ "             </Attribute>" 
				+ "         </Rule>"
				+ " </AttributeReleasePolicy>";

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		Principal principal = new LocalPrincipal("TestPrincipal");

		// test user who meets constraint
		Collection<AAAttribute> inputSet1 = new ArrayList<AAAttribute>();
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:foo", new Object[]{"bar"}));

		Collection<AAAttribute> releaseSet1 = new ArrayList<AAAttribute>();
		releaseSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		engine.filterAttributes(inputSet1, principal, "shar.example.edu");
		assertEquals("ARP application test 1a: ARP not applied as expected.", releaseSet1, inputSet1);

		// test user who does not meet constraint
		Collection<AAAttribute> inputSet2 = new ArrayList<AAAttribute>();
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		Collection<AAAttribute> releaseSet2 = new ArrayList<AAAttribute>();

		engine.filterAttributes(inputSet2, principal, "shar.example.edu");
		assertEquals("ARP application test 1b: ARP not applied as expected.", releaseSet2, inputSet2);

	}
	 /**
	 * Use Case: must have two  specific attribute values
	 * Example:  release uid only if user has two specific value for attribute "foo", "bar" and "wee"
	 */
	void arpConstraintTest4(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "         <Rule>" 
				+ "             <Constraint"
				+ "					attributeName=\"urn:mace:dir:attribute-def:foo\""
				+ "					matchFunction=\"urn:mace:shibboleth:arp:matchFunction:stringValueMatch\""
				+ "					matches=\"any\">bar</Constraint>"
				+ "             <Constraint"
				+ "					attributeName=\"urn:mace:dir:attribute-def:foo\""
				+ "					matchFunction=\"urn:mace:shibboleth:arp:matchFunction:stringValueMatch\""
				+ "					matches=\"any\">wee</Constraint>"
				+ "             <Target>" 
				+ "                 <AnyTarget/>" 
				+ "             </Target>"
				+ "             <Attribute name=\"urn:mace:dir:attribute-def:uid\">"
				+ "                 <AnyValue release=\"permit\"/>" 
				+ "             </Attribute>" 
				+ "         </Rule>"
				+ " </AttributeReleasePolicy>";

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		Principal principal = new LocalPrincipal("TestPrincipal");

		// test user who meets constraint
		Collection<AAAttribute> inputSet1 = new ArrayList<AAAttribute>();
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:foo", new Object[]{"bar"}));

		Collection<AAAttribute> releaseSet1 = new ArrayList<AAAttribute>();
		releaseSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		engine.filterAttributes(inputSet1, principal, "shar.example.edu");
		assertEquals("ARP application test 1a: ARP not applied as expected.", releaseSet1, inputSet1);

		// test user who does not meet constraint
		Collection<AAAttribute> inputSet2 = new ArrayList<AAAttribute>();
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		Collection<AAAttribute> releaseSet2 = new ArrayList<AAAttribute>();

		engine.filterAttributes(inputSet2, principal, "shar.example.edu");
		assertEquals("ARP application test 1b: ARP not applied as expected.", releaseSet2, inputSet2);

	}
	
	 /**
	 * Use Case: must not have a specific attribute value
	 * Example:  release uid only if user does not have a specific value for attribute "foo"
	 */
	void arpConstraintTest5(ArpRepository repository, Parser.DOMParser parser) throws Exception {

		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "         <Rule>" 
				+ "             <Constraint"
				+ "					attributeName=\"urn:mace:dir:attribute-def:foo\""
				+ "					matchFunction=\"urn:mace:shibboleth:arp:matchFunction:stringValueMatch\""
				+ "					matches=\"none\">bar</Constraint>"
				+ "             <Target>" 
				+ "                 <AnyTarget/>" 
				+ "             </Target>"
				+ "             <Attribute name=\"urn:mace:dir:attribute-def:uid\">"
				+ "                 <AnyValue release=\"permit\"/>" 
				+ "             </Attribute>" 
				+ "         </Rule>"
				+ " </AttributeReleasePolicy>";

		// Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		Principal principal = new LocalPrincipal("TestPrincipal");

		// test user who meets constraint
		Collection<AAAttribute> inputSet1 = new ArrayList<AAAttribute>();
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:foo", new Object[]{"bar"}));

		Collection<AAAttribute> releaseSet1 = new ArrayList<AAAttribute>();
		releaseSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		engine.filterAttributes(inputSet1, principal, "shar.example.edu");
		assertEquals("ARP application test 1a: ARP not applied as expected.", releaseSet1, inputSet1);

		// test user who does not meet constraint
		Collection<AAAttribute> inputSet2 = new ArrayList<AAAttribute>();
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		Collection<AAAttribute> releaseSet2 = new ArrayList<AAAttribute>();

		engine.filterAttributes(inputSet2, principal, "shar.example.edu");
		assertEquals("ARP application test 1b: ARP not applied as expected.", releaseSet2, inputSet2);

	}
}
