/* 
 * The Shibboleth License, Version 1. 
 * Copyright (c) 2002 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
 * 
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this 
 * list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution, if any, must include 
 * the following acknowledgment: "This product includes software developed by 
 * the University Corporation for Advanced Internet Development 
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement 
 * may appear in the software itself, if and wherever such third-party 
 * acknowledgments normally appear.
 * 
 * Neither the name of Shibboleth nor the names of its contributors, nor 
 * Internet2, nor the University Corporation for Advanced Internet Development, 
 * Inc., nor UCAID may be used to endorse or promote products derived from this 
 * software without specific prior written permission. For written permission, 
 * please contact shibboleth@shibboleth.org
 * 
 * Products derived from this software may not be called Shibboleth, Internet2, 
 * UCAID, or the University Corporation for Advanced Internet Development, nor 
 * may Shibboleth appear in their name, without prior written permission of the 
 * University Corporation for Advanced Internet Development.
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK 
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY 
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.aa.arp;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Properties;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.xerces.parsers.DOMParser;
import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XMLSerializer;
import org.xml.sax.EntityResolver;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import edu.internet2.middleware.shibboleth.aa.AAAttribute;
import edu.internet2.middleware.shibboleth.aa.AAAttributeSet;
import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;

/**
 * Validation suite for <code>Arp</code> processing.
 * 
 * @ author Walter Hoehn(wassa@columbia.edu)
 */

public class ArpTests extends TestCase {

	private DOMParser parser = new DOMParser();
	private String[] arpExamples =
		{
			"data/example1.xml",
			"data/example2.xml",
			"data/example3.xml",
			"data/example4.xml",
			"data/example5.xml",
			"data/example6.xml",
			"data/example7.xml",
			"data/example8.xml",
			"data/example9.xml",
			"data/example10.xml",
			"data/example11.xml" };

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
		try {
			parser.setFeature("http://xml.org/sax/features/validation", true);
			parser.setFeature("http://apache.org/xml/features/validation/schema", true);
			parser.setEntityResolver(new EntityResolver() {
				public InputSource resolveEntity(String publicId, String systemId) throws SAXException {

					if (systemId.endsWith("shibboleth-arp-1.0.xsd")) {
						InputStream stream;
						try {
							stream = new FileInputStream("src/schemas/shibboleth-arp-1.0.xsd");
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

	public void testArpMarshalling() {

		//Test ARP description
		try {
			InputStream inStream = new FileInputStream("data/arp1.xml");
			parser.parse(new InputSource(inStream));
			Arp arp1 = new Arp();
			arp1.marshall(parser.getDocument().getDocumentElement());
			assertEquals("ARP Description not marshalled properly", arp1.getDescription(), "Simplest possible ARP.");

			//Test Rule description
			assertEquals(
				"ARP Rule Description not marshalled properly",
				arp1.getAllRules()[0].getDescription(),
				"Example Rule Description.");
		} catch (Exception e) {
			fail("Failed to marshall ARP: " + e);
		}

		//Test case where ARP description does not exist
		try {
			InputStream inStream = new FileInputStream("data/arp2.xml");
			parser.parse(new InputSource(inStream));
			Arp arp2 = new Arp();
			arp2.marshall(parser.getDocument().getDocumentElement());
			assertNull("ARP Description not marshalled properly", arp2.getDescription());

			//Test case where ARP Rule description does not exist	
			assertNull("ARP Rule Description not marshalled properly", arp2.getAllRules()[0].getDescription());
		} catch (Exception e) {
			fail("Failed to marshall ARP.");
		}

	}

	public void testMatchingFunctions() {

		try {

			/*
			 * Test Arp Engine function retrieval
			 */

			//Lookup a function that doesn't exist
			MatchFunction noFunction =
				ArpEngine.lookupMatchFunction(new URI("urn:mace:shibboleth:arp:matchFunction:dummy"));
			assertNull("ArpEngine did not return null on dummy function.", noFunction);

			//Lookup some real functions
			MatchFunction exactSharFunction =
				ArpEngine.lookupMatchFunction(new URI("urn:mace:shibboleth:arp:matchFunction:exactShar"));
			assertNotNull("ArpEngine did not properly load the Exact SHAR function.", exactSharFunction);
			MatchFunction resourceTreeFunction =
				ArpEngine.lookupMatchFunction(new URI("urn:mace:shibboleth:arp:matchFunction:resourceTree"));
			assertNotNull("ArpEngine did not properly load the Resource Tree SHAR function.", resourceTreeFunction);
			MatchFunction regexFunction =
				ArpEngine.lookupMatchFunction(new URI("urn:mace:shibboleth:arp:matchFunction:regexMatch"));
			assertNotNull("ArpEngine did not properly load the Regex function.", regexFunction);

			/* 
			 * Test the Exact SHAR function (requester)
			 */

			assertTrue(
				"Exact SHAR function: false negative",
				exactSharFunction.match("shar.example.edu", "shar.example.edu"));
			assertTrue(
				"Exact SHAR function: false negative",
				!exactSharFunction.match("shar.example.edu", "www.example.edu"));
			assertTrue(
				"Exact SHAR function: false negative",
				!exactSharFunction.match("example.edu", "shar.example.edu"));

			//Make sure we properly handle bad input
			try {
				exactSharFunction.match(null, null);
				fail("Exact SHAR function seems to take improper input without throwing an exception.");
			} catch (ArpException ie) {
				//This is supposed to fail
			}

			/*
			 * Test the Resource Tree function (resource)
			 */

			URL requestURL1 = new URL("http://www.example.edu/test/");
			URL requestURL2 = new URL("http://www.example.edu/test/index.html");
			URL requestURL3 = new URL("http://www.example.edu/test2/index.html");
			URL requestURL4 = new URL("http://www.example.edu/test2/index.html?test1=test1");

			assertTrue(
				"Resource Tree function: false negative",
				resourceTreeFunction.match("http://www.example.edu/", requestURL1));
			assertTrue(
				"Resource Tree function: false positive",
				!resourceTreeFunction.match("https://www.example.edu/", requestURL1));
			assertTrue(
				"Resource Tree function: false negative",
				resourceTreeFunction.match("http://www.example.edu:80/", requestURL1));
			assertTrue(
				"Resource Tree function: false positive",
				!resourceTreeFunction.match("http://www.example.edu:81/", requestURL1));
			assertTrue(
				"Resource Tree function: false negative",
				resourceTreeFunction.match("http://www.example.edu/test/", requestURL1));
			assertTrue(
				"Resource Tree function: false negative",
				resourceTreeFunction.match("http://www.example.edu/test/", requestURL2));
			assertTrue(
				"Resource Tree function: false negative",
				resourceTreeFunction.match("http://www.example.edu/", requestURL3));
			assertTrue(
				"Resource Tree function: false positive",
				!resourceTreeFunction.match("http://www.example.edu/test/", requestURL3));
			assertTrue(
				"Resource Tree function: false negative",
				resourceTreeFunction.match("http://www.example.edu/test2/index.html", requestURL3));
			assertTrue(
				"Resource Tree function: false negative",
				resourceTreeFunction.match("http://www.example.edu/test2/index.html", requestURL4));
			assertTrue(
				"Resource Tree function: false negative",
				resourceTreeFunction.match("http://www.example.edu/test2/index.html?test1=test1", requestURL4));
			assertTrue(
				"Resource Tree function: false positive",
				!resourceTreeFunction.match("http://www.example.edu/test2/index.html?test1=test1", requestURL3));

			//Make sure we properly handle bad input
			try {
				resourceTreeFunction.match(null, null);
				fail("Resource Tree function seems to take improper input without throwing an exception.");
			} catch (ArpException ie) {
				//This is supposed to fail
			}
			try {
				resourceTreeFunction.match("Test", "Test");
				fail("Resource Tree function seems to take improper input without throwing an exception.");
			} catch (ArpException ie) {
				//This is supposed to fail
			}

			/*
			 * Test the Regex function (requester & resource)
			 */

			//Try requester regexes
			assertTrue(
				"Regex function: false negative",
				regexFunction.match("^shar\\.example\\.edu$", "shar.example.edu"));
			assertTrue(
				"Regex function: false negative",
				regexFunction.match("^.*\\.example\\.edu$", "shar.example.edu"));
			assertTrue(
				"Regex function: false negative",
				regexFunction.match("^shar[1-9]?\\.example\\.edu$", "shar1.example.edu"));
			assertTrue("Regex function: false negative", regexFunction.match(".*\\.edu", "shar.example.edu"));
			assertTrue(
				"Regex function: false positive",
				!regexFunction.match("^shar[1-9]\\.example\\.edu$", "shar.example.edu"));
			assertTrue(
				"Regex function: false positive",
				!regexFunction.match("^shar\\.example\\.edu$", "www.example.edu"));
			assertTrue(
				"Regex function: false positive",
				!regexFunction.match("^shar\\.example\\.edu$", "www.example.com"));

			//Try resource regexes
			assertTrue(
				"Regex function: false negative",
				regexFunction.match("^http://www\\.example\\.edu/.*$", requestURL1));
			assertTrue(
				"Regex function: false negative",
				regexFunction.match("^http://www\\.example\\.edu/.*$", requestURL2));
			assertTrue(
				"Regex function: false negative",
				regexFunction.match("^http://.*\\.example\\.edu/.*$", requestURL2));
			assertTrue(
				"Regex function: false negative",
				regexFunction.match("^https?://.*\\.example\\.edu/.*$", requestURL2));
			assertTrue("Regex function: false negative", regexFunction.match(".*", requestURL2));
			assertTrue(
				"Regex function: false positive",
				!regexFunction.match("^https?://.*\\.example\\.edu/$", requestURL2));
			assertTrue(
				"Regex function: false positive",
				!regexFunction.match("^https?://www\\.example\\.edu/test/$", requestURL3));

			//Make sure we properly handle bad input
			try {
				regexFunction.match(null, null);
				fail("Regex function seems to take improper input without throwing an exception.");
			} catch (ArpException ie) {
				//This is supposed to fail
			}

		} catch (ArpException e) {
			fail("Encountered a problem loading match function: " + e);
		} catch (URISyntaxException e) {
			fail("Unable to create URI from test string.");
		} catch (MalformedURLException e) {
			fail("Couldn't create test URLs: " + e);
		}

	}

	public void testRepositories() {

		/*
		 * Test the Factory
		 */

		//Make sure we fail if no Repository is specified
		Properties props = new Properties();
		try {
			ArpRepositoryFactory.getInstance(props);
		} catch (ArpRepositoryException e) {
			//This is supposed to fail
		}

		// Make sure we can create an Arp Repository
		props.setProperty(
			"edu.internet2.middleware.shibboleth.aa.arp.ArpRepository.implementation",
			"edu.internet2.middleware.shibboleth.aa.arp.provider.MemoryArpRepository");
		ArpRepository repository = null;
		try {
			repository = ArpRepositoryFactory.getInstance(props);
		} catch (ArpRepositoryException e) {
			fail("Failed to create memory-based Arp Repository" + e);
		}
		assertNotNull("Failed to create memory-based Arp Repository: Factory returned null.", repository);

		/*
		 * Exercise the Memory Arp Repository
		 */

		//Set/retrieve/remove a Site ARP
		Arp siteArp1 = new Arp();
		siteArp1.setDescription("Test Site Arp 1.");
		try {
			repository.update(siteArp1);
			assertEquals(
				"Memory Repository does not store and retrieve Site ARPs properly.",
				siteArp1,
				repository.getSitePolicy());
			repository.remove(repository.getSitePolicy());
			assertNull("Memorty Repository does not properly delete Site ARPs.", repository.getSitePolicy());
		} catch (ArpRepositoryException e) {
			fail("Error adding Site ARP to Memory Repository.");
		}

		//Set/retrieve/delete some user ARPs
		Arp userArp1 = new Arp();
		userArp1.setDescription("Broken User Arp 1.");
		try {
			repository.update(userArp1);
			assertTrue(
				"Memory Repository does not store and retrieve User ARPs properly.",
				(!userArp1.equals(repository.getUserPolicy(userArp1.getPrincipal()))));
		} catch (ArpRepositoryException e) {
			fail("Error adding User ARP to Memory Repository.");
		}

		Arp userArp2 = new Arp(new AuthNPrincipal("TestPrincipal"));
		userArp2.setDescription("Test User Arp 2.");
		try {
			repository.update(userArp2);
			assertEquals(
				"Memory Repository does not store and retrieve User ARPs properly.",
				userArp2,
				repository.getUserPolicy(userArp2.getPrincipal()));
			repository.remove(repository.getUserPolicy(userArp2.getPrincipal()));
			assertNull(
				"Memorty Repository does not properly delete User ARPs.",
				repository.getUserPolicy(userArp2.getPrincipal()));
		} catch (ArpRepositoryException e) {
			fail("Error adding User ARP to Memory Repository.");
		}

		/*
		 * Exercise the Memory Arp Repository
		 */

		//create a repository
		props.setProperty(
			"edu.internet2.middleware.shibboleth.aa.arp.ArpRepository.implementation",
			"edu.internet2.middleware.shibboleth.aa.arp.provider.FileSystemArpRepository");
		props.setProperty(
			"edu.internet2.middleware.shibboleth.aa.arp.provider.FileSystemArpRepository.Path",
			new File("data/").toURI().toString());
		props.setProperty("edu.internet2.middleware.shibboleth.aa.arp.BaseArpRepository.ArpTTL", "65535");
		repository = null;
		try {
			repository = ArpRepositoryFactory.getInstance(props);
		} catch (ArpRepositoryException e) {
			fail("Failed to create file-based Arp Repository" + e.getMessage());
		}
		assertNotNull("Failed to create file-based Arp Repository: Factory returned null.", repository);

		try {
			Arp siteArp = repository.getSitePolicy();

			InputStream inStream = new FileInputStream("data/arp.site.xml");
			parser.parse(new InputSource(inStream));
			ByteArrayOutputStream directXML = new ByteArrayOutputStream();
			new XMLSerializer(directXML, new OutputFormat()).serialize(parser.getDocument().getDocumentElement());

			ByteArrayOutputStream processedXML = new ByteArrayOutputStream();
			new XMLSerializer(processedXML, new OutputFormat()).serialize(siteArp.unmarshall());

			assertTrue(
				"File-based ARP Repository did not return the correct site ARP.",
				directXML.toString().replaceAll(">[\t\r\n ]+<", "><").equals(
					processedXML.toString().replaceAll(">[\t\r\n ]+<", "><")));

			Arp userArp = repository.getUserPolicy(new AuthNPrincipal("test"));

			inStream = new FileInputStream("data/arp.user.test.xml");
			parser.parse(new InputSource(inStream));
			directXML = new ByteArrayOutputStream();
			new XMLSerializer(directXML, new OutputFormat()).serialize(parser.getDocument().getDocumentElement());

			processedXML = new ByteArrayOutputStream();
			new XMLSerializer(processedXML, new OutputFormat()).serialize(userArp.unmarshall());

			assertTrue(
				"File-based ARP Repository did not return the correct user ARP.",
				directXML.toString().replaceAll(">[\t\r\n ]+<", "><").equals(
					processedXML.toString().replaceAll(">[\t\r\n ]+<", "><")));

			Arp[] allArps = repository.getAllPolicies(new AuthNPrincipal("test"));

			assertTrue("File-based ARP Repository did not return the correct number of ARPs.", (allArps.length == 2));

		} catch (Exception e) {
			fail("Error retrieving ARP from Repository: " + e);
		}

	}

	public void testPossibleReleaseSetComputation() {
		Properties props = new Properties();
		props.setProperty(
			"edu.internet2.middleware.shibboleth.aa.arp.ArpRepository.implementation",
			"edu.internet2.middleware.shibboleth.aa.arp.provider.MemoryArpRepository");
		ArpRepository repository = null;
		try {
			repository = ArpRepositoryFactory.getInstance(props);
		} catch (ArpRepositoryException e) {
			fail("Failed to create memory-based Arp Repository" + e);
		}

		try {
			Principal principal1 = new AuthNPrincipal("TestPrincipal");
			URL url1 = new URL("http://www.example.edu/");
			URI[] list1 = { new URI("urn:mace:eduPerson:1.0:eduPersonAffiliation")};
			URI[] list2 =
				{
					new URI("urn:mace:eduPerson:1.0:eduPersonAffiliation"),
					new URI("urn:mace:eduPerson:1.0:eduPersonPrincipalName")};
			URI[] list3 = new URI[0];

			//Test with just a site ARP
			InputStream inStream = new FileInputStream("data/arp1.xml");
			parser.parse(new InputSource(inStream));
			Arp arp1 = new Arp();
			arp1.marshall(parser.getDocument().getDocumentElement());
			repository.update(arp1);
			ArpEngine engine = new ArpEngine(repository, props);
			URI[] possibleAttributes = engine.listPossibleReleaseAttributes(principal1, "shar.example.edu", url1);
			assertEquals(
				"Incorrectly computed possible release set (1).",
				new HashSet(Arrays.asList(possibleAttributes)),
				new HashSet(Arrays.asList(list1)));

			//Test with site and user ARPs
			inStream = new FileInputStream("data/arp7.xml");
			parser.parse(new InputSource(inStream));
			Arp arp7 = new Arp();
			arp7.setPrincipal(principal1);
			arp7.marshall(parser.getDocument().getDocumentElement());
			repository.update(arp7);
			possibleAttributes = engine.listPossibleReleaseAttributes(principal1, "shar.example.edu", url1);
			assertEquals(
				"Incorrectly computed possible release set (2).",
				new HashSet(Arrays.asList(possibleAttributes)),
				new HashSet(Arrays.asList(list2)));

			//Ensure that explicit denies on any value are not in the release set
			inStream = new FileInputStream("data/arp6.xml");
			parser.parse(new InputSource(inStream));
			Arp arp6 = new Arp();
			arp6.setPrincipal(principal1);
			arp6.marshall(parser.getDocument().getDocumentElement());
			repository.update(arp6);
			possibleAttributes = engine.listPossibleReleaseAttributes(principal1, "shar.example.edu", url1);
			assertEquals(
				"Incorrectly computed possible release set (3).",
				new HashSet(Arrays.asList(possibleAttributes)),
				new HashSet(Arrays.asList(list3)));

		} catch (Exception e) {
			e.printStackTrace();
			fail("Failed to marshall ARP: " + e);
		}

	}

	public void testArpApplication() {

		//Setup a test ARP repository
		Properties props = new Properties();
		props.setProperty(
			"edu.internet2.middleware.shibboleth.aa.arp.ArpRepository.implementation",
			"edu.internet2.middleware.shibboleth.aa.arp.provider.MemoryArpRepository");
		ArpRepository repository = null;
		try {
			repository = ArpRepositoryFactory.getInstance(props);
		} catch (ArpRepositoryException e) {
			fail("Failed to create memory-based Arp Repository" + e);
		}

		try {

			arpApplicationTest1(repository, props, parser);
			arpApplicationTest2(repository, props, parser);
			arpApplicationTest3(repository, props, parser);
			arpApplicationTest4(repository, props, parser);
			arpApplicationTest5(repository, props, parser);
			arpApplicationTest6(repository, props, parser);
			arpApplicationTest7(repository, props, parser);
			arpApplicationTest8(repository, props, parser);
			arpApplicationTest9(repository, props, parser);
			arpApplicationTest10(repository, props, parser);
			arpApplicationTest11(repository, props, parser);
			arpApplicationTest12(repository, props, parser);
			arpApplicationTest13(repository, props, parser);
			arpApplicationTest14(repository, props, parser);
			arpApplicationTest15(repository, props, parser);
			arpApplicationTest16(repository, props, parser);
			arpApplicationTest17(repository, props, parser);
			arpApplicationTest18(repository, props, parser);
			arpApplicationTest19(repository, props, parser);
			arpApplicationTest20(repository, props, parser);
			arpApplicationTest21(repository, props, parser);

		} catch (Exception e) {
			e.printStackTrace();
			fail("Failed to apply filter to ARPs: " + e);
		}
	}

	public void testRoundtripMarshalling() {

		try {
			for (int i = 0; i < arpExamples.length; i++) {

				InputStream inStream = new FileInputStream(arpExamples[i]);
				parser.parse(new InputSource(inStream));
				ByteArrayOutputStream directXML = new ByteArrayOutputStream();
				new XMLSerializer(directXML, new OutputFormat()).serialize(parser.getDocument().getDocumentElement());

				Arp arp1 = new Arp();
				arp1.marshall(parser.getDocument().getDocumentElement());

				ByteArrayOutputStream processedXML = new ByteArrayOutputStream();
				new XMLSerializer(processedXML, new OutputFormat()).serialize(arp1.unmarshall());

				assertTrue(
					"Round trip marshall/unmarshall failed for file (" + arpExamples[i] + ")",
					directXML.toString().replaceAll(">[\t\r\n ]+<", "><").equals(
						processedXML.toString().replaceAll(">[\t\r\n ]+<", "><")));
			}

		} catch (Exception e) {
			fail("Failed to marshall ARP: " + e);
		}

	}
	/**
	 * ARPs: A site ARP only
	 * Target: Any
	 * Attribute: Any value release,
	 */
	void arpApplicationTest1(ArpRepository repository, Properties props, DOMParser parser) throws Exception {

		//Gather the Input
		String rawArp =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<AnyTarget/>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new AuthNPrincipal("TestPrincipal");
		URL url1 = new URL("http://www.example.edu/");
		AAAttributeSet inputSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "member@example.edu", "faculty@example.edu" }));

		AAAttributeSet releaseSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "member@example.edu", "faculty@example.edu" }));

		//Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository, props);

		//Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu", url1);

		assertEquals("ARP application test 1: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP only
	 * Target: Any
	 * Attribute: Any value release, implicit deny
	 */
	void arpApplicationTest2(ArpRepository repository, Properties props, DOMParser parser) throws Exception {

		//Gather the Input
		String rawArp =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<AnyTarget/>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new AuthNPrincipal("TestPrincipal");
		URL url1 = new URL("http://www.example.edu/");
		AAAttributeSet inputSet =
			new AAAttributeSet(
				new AAAttribute[] {
					new AAAttribute(
						"urn:mace:eduPerson:1.0:eduPersonAffiliation",
						new Object[] { "member@example.edu", "faculty@example.edu" }),
					new AAAttribute(
						"urn:mace:eduPerson:1.0:eduPersonPrincipalName",
						new Object[] { "mehoehn@example.edu" })
		});

		AAAttributeSet releaseSet =
			new AAAttributeSet(
				new AAAttribute[] {
					 new AAAttribute(
						"urn:mace:eduPerson:1.0:eduPersonAffiliation",
						new Object[] { "member@example.edu", "faculty@example.edu" })
		});

		//Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository, props);

		//Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu", url1);

		assertEquals("ARP application test 2: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP only
	 * Target: Any
	 * Attribute: One value release
	 */
	void arpApplicationTest3(ArpRepository repository, Properties props, DOMParser parser) throws Exception {

		//Gather the Input
		String rawArp =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<AnyTarget/>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<Value release=\"permit\">member@example.edu</Value>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new AuthNPrincipal("TestPrincipal");
		URL url1 = new URL("http://www.example.edu/");
		AAAttributeSet inputSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "member@example.edu", "faculty@example.edu" }));
		AAAttributeSet releaseSet =
			new AAAttributeSet(
				new AAAttribute("urn:mace:eduPerson:1.0:eduPersonAffiliation", new Object[] { "member@example.edu" }));

		//Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository, props);

		//Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu", url1);

		assertEquals("ARP application test 3: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP only
	 * Target: Any
	 * Attribute: Any value except one release, canonical representation
	 */
	void arpApplicationTest4(ArpRepository repository, Properties props, DOMParser parser) throws Exception {

		//Gather the Input
		String rawArp =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<AnyTarget/>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>"
				+ "					<Value release=\"deny\">member@example.edu</Value>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new AuthNPrincipal("TestPrincipal");
		URL url1 = new URL("http://www.example.edu/");
		AAAttributeSet inputSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "member@example.edu", "faculty@example.edu", "employee@example.edu" }));
		AAAttributeSet releaseSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "faculty@example.edu", "employee@example.edu" }));

		//Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository, props);

		//Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu", url1);

		assertEquals("ARP application test 4: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP only
	 * Target: Any
	 * Attribute: Any value except one release, expanded representation
	 */
	void arpApplicationTest5(ArpRepository repository, Properties props, DOMParser parser) throws Exception {

		//Gather the Input
		String rawArp =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<AnyTarget/>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>"
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<Value release=\"deny\">member@example.edu</Value>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new AuthNPrincipal("TestPrincipal");
		URL url1 = new URL("http://www.example.edu/");
		AAAttributeSet inputSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "member@example.edu", "faculty@example.edu", "employee@example.edu" }));
		AAAttributeSet releaseSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "faculty@example.edu", "employee@example.edu" }));

		//Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository, props);

		//Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu", url1);

		assertEquals("ARP application test 5: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP only
	 * Target: Any
	 * Attribute: Any value except two release, expanded representation
	 */
	void arpApplicationTest6(ArpRepository repository, Properties props, DOMParser parser) throws Exception {

		//Gather the Input
		String rawArp =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<AnyTarget/>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>"
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<Value release=\"deny\">member@example.edu</Value>"
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<Value release=\"deny\">faculty@example.edu</Value>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new AuthNPrincipal("TestPrincipal");
		URL url1 = new URL("http://www.example.edu/");
		AAAttributeSet inputSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "member@example.edu", "faculty@example.edu", "employee@example.edu" }));
		AAAttributeSet releaseSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "employee@example.edu" }));

		//Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository, props);

		//Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu", url1);

		assertEquals("ARP application test 6: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP only
	 * Target: Any
	 * Attribute: Two value release, canonical representation
	 */
	void arpApplicationTest7(ArpRepository repository, Properties props, DOMParser parser) throws Exception {

		//Gather the Input
		String rawArp =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<AnyTarget/>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<Value release=\"permit\">member@example.edu</Value>"
				+ "					<Value release=\"permit\">faculty@example.edu</Value>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new AuthNPrincipal("TestPrincipal");
		URL url1 = new URL("http://www.example.edu/");
		AAAttributeSet inputSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "member@example.edu", "faculty@example.edu", "employee@example.edu" }));
		AAAttributeSet releaseSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "member@example.edu", "faculty@example.edu" }));

		//Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository, props);

		//Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu", url1);

		assertEquals("ARP application test 3: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP only
	 * Target: Any
	 * Attribute: Two value release, expanded representation
	 */
	void arpApplicationTest8(ArpRepository repository, Properties props, DOMParser parser) throws Exception {

		//Gather the Input
		String rawArp =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<AnyTarget/>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<Value release=\"permit\">member@example.edu</Value>"
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<Value release=\"permit\">faculty@example.edu</Value>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new AuthNPrincipal("TestPrincipal");
		URL url1 = new URL("http://www.example.edu/");
		AAAttributeSet inputSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "member@example.edu", "faculty@example.edu", "employee@example.edu" }));
		AAAttributeSet releaseSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "member@example.edu", "faculty@example.edu" }));

		//Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository, props);

		//Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu", url1);

		assertEquals("ARP application test 8: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP only
	 * Target: Any
	 * Attribute: Any value deny
	 */
	void arpApplicationTest9(ArpRepository repository, Properties props, DOMParser parser) throws Exception {

		//Gather the Input
		String rawArp =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<AnyTarget/>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"deny\"/>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new AuthNPrincipal("TestPrincipal");
		URL url1 = new URL("http://www.example.edu/");
		AAAttributeSet inputSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "member@example.edu", "faculty@example.edu" }));

		//Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository, props);

		//Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu", url1);

		assertEquals("ARP application test 9: ARP not applied as expected.", inputSet, new AAAttributeSet());
	}

	/**
	 * ARPs: A site ARP only
	 * Target: Any
	 * Attribute: Any value deny trumps explicit permit expanded representation
	 */
	void arpApplicationTest10(ArpRepository repository, Properties props, DOMParser parser) throws Exception {

		//Gather the Input
		String rawArp =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<AnyTarget/>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"deny\"/>"
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<Value release=\"permit\">member@example.edu</Value>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new AuthNPrincipal("TestPrincipal");
		URL url1 = new URL("http://www.example.edu/");
		AAAttributeSet inputSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "member@example.edu", "faculty@example.edu" }));

		//Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository, props);

		//Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu", url1);

		assertEquals("ARP application test 10: ARP not applied as expected.", inputSet, new AAAttributeSet());
	}

	/**
	 * ARPs: A site ARP only
	 * Target: Any
	 * Attribute: Any value deny trumps explicit permit canonical representation
	 */
	void arpApplicationTest11(ArpRepository repository, Properties props, DOMParser parser) throws Exception {

		//Gather the Input
		String rawArp =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<AnyTarget/>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"deny\"/>"
				+ "					<Value release=\"permit\">member@example.edu</Value>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new AuthNPrincipal("TestPrincipal");
		URL url1 = new URL("http://www.example.edu/");
		AAAttributeSet inputSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "member@example.edu", "faculty@example.edu" }));

		//Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository, props);

		//Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu", url1);

		assertEquals("ARP application test 11: ARP not applied as expected.", inputSet, new AAAttributeSet());
	}

	/**
	 * ARPs: A site ARP only
	 * Target: Specific shar, Any Resource
	 * Attribute: Any value release
	 */
	void arpApplicationTest12(ArpRepository repository, Properties props, DOMParser parser) throws Exception {

		//Gather the Input
		String rawArp =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<Requester>shar.example.edu</Requester>"
				+ "					<AnyResource />"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new AuthNPrincipal("TestPrincipal");
		URL url1 = new URL("http://www.example.edu/");
		AAAttributeSet inputSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "member@example.edu", "faculty@example.edu" }));
		AAAttributeSet releaseSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "member@example.edu", "faculty@example.edu" }));

		//Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository, props);

		//Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu", url1);

		assertEquals("ARP application test 12: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP only
	 * Target: Specific shar, Any Resource (another example)
	 * Attribute: Any value release
	 */
	void arpApplicationTest13(ArpRepository repository, Properties props, DOMParser parser) throws Exception {

		//Gather the Input
		String rawArp =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<Requester>shar.example.edu</Requester>"
				+ "					<AnyResource />"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new AuthNPrincipal("TestPrincipal");
		URL url1 = new URL("https://foo.com/");
		AAAttributeSet inputSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "member@example.edu", "faculty@example.edu" }));
		AAAttributeSet releaseSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "member@example.edu", "faculty@example.edu" }));

		//Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository, props);

		//Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu", url1);

		assertEquals("ARP application test 13: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP only
	 * Target: Specific shar (no match), Any Resource
	 * Attribute: Any value release
	 */
	void arpApplicationTest14(ArpRepository repository, Properties props, DOMParser parser) throws Exception {

		//Gather the Input
		String rawArp =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<Requester>shar.example.edu</Requester>"
				+ "					<AnyResource />"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new AuthNPrincipal("TestPrincipal");
		URL url1 = new URL("http://www.example.edu/");
		AAAttributeSet inputSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "member@example.edu", "faculty@example.edu" }));

		//Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository, props);

		//Apply the ARP
		engine.filterAttributes(inputSet, principal1, "www.example.edu", url1);

		assertEquals("ARP application test 14: ARP not applied as expected.", inputSet, new AAAttributeSet());
	}

	/**
	 * ARPs: A site ARP only
	 * Target: Specific shar, Specific resource
	 * Attribute: Any value release
	 */
	void arpApplicationTest15(ArpRepository repository, Properties props, DOMParser parser) throws Exception {

		//Gather the Input
		String rawArp =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<Requester>shar.example.edu</Requester>"
				+ "					<Resource>http://www.example.edu/</Resource>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new AuthNPrincipal("TestPrincipal");
		URL url1 = new URL("http://www.example.edu/index.html");
		AAAttributeSet inputSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "member@example.edu", "faculty@example.edu" }));
		AAAttributeSet releaseSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "member@example.edu", "faculty@example.edu" }));

		//Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository, props);

		//Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu", url1);

		assertEquals("ARP application test 15: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP only
	 * Target: Specific shar, Specific resource (no match)
	 * Attribute: Any value release
	 */
	void arpApplicationTest16(ArpRepository repository, Properties props, DOMParser parser) throws Exception {

		//Gather the Input
		String rawArp =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<Requester>shar.example.edu</Requester>"
				+ "					<Resource>http://www.example.edu/</Resource>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new AuthNPrincipal("TestPrincipal");
		URL url1 = new URL("https://www.example.edu/index.html");
		AAAttributeSet inputSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "member@example.edu", "faculty@example.edu" }));

		//Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository, props);

		//Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu", url1);

		assertEquals("ARP application test 16: ARP not applied as expected.", inputSet, new AAAttributeSet());
	}

	/**
	 * ARPs: A site ARP only
	 * Target: Multiple matching rules
	 * Attribute: various
	 */
	void arpApplicationTest17(ArpRepository repository, Properties props, DOMParser parser) throws Exception {

		//Gather the Input
		String rawArp =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<AnyTarget />"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<Requester>shar1.example.edu</Requester>"
				+ "					<AnyResource />"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<Value release=\"deny\">faculty@example.edu</Value>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<Requester matchFunction=\"urn:mace:shibboleth:arp:matchFunction:regexMatch\">shar[1-9]\\.example\\.edu</Requester>"
				+ "					<Resource matchFunction=\"urn:mace:shibboleth:arp:matchFunction:regexMatch\">^https?://.+\\.example\\.edu/.*$</Resource>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonPrincipalName\">"
				+ "					<AnyValue release=\"permit\"/>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new AuthNPrincipal("TestPrincipal");
		URL url1 = new URL("https://www.example.edu/index.html");
		AAAttributeSet inputSet =
			new AAAttributeSet(
				new AAAttribute[] {
					new AAAttribute(
						"urn:mace:eduPerson:1.0:eduPersonAffiliation",
						new Object[] { "member@example.edu", "faculty@example.edu" }),
					new AAAttribute(
						"urn:mace:eduPerson:1.0:eduPersonPrincipalName",
						new Object[] { "wassa@columbia.edu" })
		});

		AAAttributeSet releaseSet =
			new AAAttributeSet(
				new AAAttribute[] {
					new AAAttribute(
						"urn:mace:eduPerson:1.0:eduPersonPrincipalName",
						new Object[] { "wassa@columbia.edu" }),
					new AAAttribute(
						"urn:mace:eduPerson:1.0:eduPersonAffiliation",
						new Object[] { "member@example.edu" })
		});

		//Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository, props);

		//Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar1.example.edu", url1);

		assertEquals("ARP application test 17: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP only
	 * Target: Any
	 * Attribute: Any value release of two attributes in one rule
	 */
	void arpApplicationTest18(ArpRepository repository, Properties props, DOMParser parser) throws Exception {

		//Gather the Input
		String rawArp =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<AnyTarget/>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>"
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonPrincipalName\">"
				+ "					<AnyValue release=\"permit\"/>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new AuthNPrincipal("TestPrincipal");
		URL url1 = new URL("http://www.example.edu/");
		AAAttributeSet inputSet =
			new AAAttributeSet(
				new AAAttribute[] {
					new AAAttribute(
						"urn:mace:eduPerson:1.0:eduPersonAffiliation",
						new Object[] { "member@example.edu", "faculty@example.edu" }),
					new AAAttribute(
						"urn:mace:eduPerson:1.0:eduPersonPrincipalName",
						new Object[] { "mehoehn@example.edu" })
		});

		AAAttributeSet releaseSet =
			new AAAttributeSet(
				new AAAttribute[] {
					new AAAttribute(
						"urn:mace:eduPerson:1.0:eduPersonAffiliation",
						new Object[] { "member@example.edu", "faculty@example.edu" }),
					new AAAttribute(
						"urn:mace:eduPerson:1.0:eduPersonPrincipalName",
						new Object[] { "mehoehn@example.edu" })
		});

		//Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository, props);

		//Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu", url1);

		assertEquals("ARP application test 18: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A user ARP only
	 * Target: Any
	 * Attribute: Any value release,
	 */
	void arpApplicationTest19(ArpRepository repository, Properties props, DOMParser parser) throws Exception {

		//Gather the Input
		String rawArp =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<AnyTarget/>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new AuthNPrincipal("TestPrincipal");
		URL url1 = new URL("http://www.example.edu/");
		AAAttributeSet inputSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "member@example.edu", "faculty@example.edu" }));
		AAAttributeSet releaseSet =
			new AAAttributeSet(
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonAffiliation",
					new Object[] { "member@example.edu", "faculty@example.edu" }));

		//Setup the engine
		parser.parse(new InputSource(new StringReader(rawArp)));
		Arp userArp = new Arp();
		userArp.setPrincipal(principal1);
		userArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(userArp);
		ArpEngine engine = new ArpEngine(repository, props);

		//Apply the ARP
		engine.filterAttributes(inputSet, principal1, "shar.example.edu", url1);

		assertEquals("ARP application test 19: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP and user ARP
	 * Target: various
	 * Attribute: various combinations
	 */
	void arpApplicationTest20(ArpRepository repository, Properties props, DOMParser parser) throws Exception {

		//Gather the Input
		String rawSiteArp =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<AnyTarget/>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<Value release=\"permit\">member@example.edu</Value>"
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:inetOrgPerson:preferredLanguage\">"
				+ "					<AnyValue release=\"permit\" />"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<Requester matchFunction=\"urn:mace:shibboleth:arp:matchFunction:regexMatch\">.*\\.example\\.edu</Requester>"
				+ "					<AnyResource />"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonPrincipalName\">"
				+ "					<AnyValue release=\"permit\"/>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<Requester>www.example.edu</Requester>"
				+ "					<Resource>http://www.example.edu/</Resource>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>"
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonEntitlement\">"
				+ "					<Value release=\"permit\">urn:example:contract:4657483</Value>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<Requester>www.external.com</Requester>"
				+ "					<Resource>http://www.external.com/</Resource>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonEntitlement\">"
				+ "					<Value release=\"permit\">urn:example:contract:113455</Value>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		String rawUserArp =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<AnyTarget/>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonEntitlement\">"
				+ "					<Value release=\"deny\">urn:example:poorlyDressed</Value>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<Requester matchFunction=\"urn:mace:shibboleth:arp:matchFunction:regexMatch\">.*\\.example\\.edu</Requester>"
				+ "					<AnyResource />"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<Value release=\"deny\">faculty@example.edu</Value>"
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonEntitlement\">"
				+ "					<Value release=\"permit\">urn:example:lovesIceCream</Value>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new AuthNPrincipal("TestPrincipal");
		URL url1 = new URL("http://www.example.edu/test/index.html");

		AAAttributeSet inputSet =
			new AAAttributeSet(
				new AAAttribute[] {
					new AAAttribute(
						"urn:mace:eduPerson:1.0:eduPersonEntitlement",
						new Object[] {
							"urn:example:lovesIceCream",
							"urn:example:poorlyDressed",
							"urn:example:contract:113455",
							"urn:example:contract:4657483" }),
					new AAAttribute(
						"urn:mace:eduPerson:1.0:eduPersonAffiliation",
						new Object[] { "member@example.edu", "faculty@example.edu", "employee@example.edu" }),
					new AAAttribute(
						"urn:mace:eduPerson:1.0:eduPersonPrincipalName",
						new Object[] { "wassa@example.edu" }),
					new AAAttribute("urn:mace:inetOrgPerson:preferredLanguage", new Object[] { "EO" })
		});

		AAAttributeSet releaseSet =
			new AAAttributeSet(
				new AAAttribute[] {
					new AAAttribute(
						"urn:mace:eduPerson:1.0:eduPersonEntitlement",
						new Object[] { "urn:example:lovesIceCream", "urn:example:contract:4657483" }),
					new AAAttribute(
						"urn:mace:eduPerson:1.0:eduPersonAffiliation",
						new Object[] { "member@example.edu", "employee@example.edu" }),
					new AAAttribute(
						"urn:mace:eduPerson:1.0:eduPersonPrincipalName",
						new Object[] { "wassa@example.edu" }),
					new AAAttribute("urn:mace:inetOrgPerson:preferredLanguage", new Object[] { "EO" })
		});

		//Add the site ARP
		parser.parse(new InputSource(new StringReader(rawSiteArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);

		//Add the user ARP
		parser.parse(new InputSource(new StringReader(rawUserArp)));
		Arp userArp = new Arp();
		userArp.setPrincipal(principal1);
		userArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(userArp);

		ArpEngine engine = new ArpEngine(repository, props);

		//Apply the ARP
		engine.filterAttributes(inputSet, principal1, "www.example.edu", url1);

		assertEquals("ARP application test 20: ARP not applied as expected.", inputSet, releaseSet);
	}

	/**
	 * ARPs: A site ARP and user ARP
	 * Target: various
	 * Attribute: various combinations (same ARPs as 20, different requester)
	 */
	void arpApplicationTest21(ArpRepository repository, Properties props, DOMParser parser) throws Exception {

		//Gather the Input
		String rawSiteArp =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<AnyTarget/>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<Value release=\"permit\">member@example.edu</Value>"
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:inetOrgPerson:preferredLanguage\">"
				+ "					<AnyValue release=\"permit\" />"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<Requester matchFunction=\"urn:mace:shibboleth:arp:matchFunction:regexMatch\">.*\\.example\\.edu</Requester>"
				+ "					<AnyResource />"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonPrincipalName\">"
				+ "					<AnyValue release=\"permit\"/>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<Requester>www.example.edu</Requester>"
				+ "					<Resource>http://www.example.edu/</Resource>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<AnyValue release=\"permit\"/>"
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonEntitlement\">"
				+ "					<Value release=\"permit\">urn:example:contract:4657483</Value>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<Requester>www.external.com</Requester>"
				+ "					<Resource>http://www.external.com/</Resource>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonEntitlement\">"
				+ "					<Value release=\"permit\">urn:example:contract:113455</Value>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		String rawUserArp =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<AnyTarget/>"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonEntitlement\">"
				+ "					<Value release=\"deny\">urn:example:poorlyDressed</Value>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "			<Rule>"
				+ "				<Target>"
				+ "					<Requester matchFunction=\"urn:mace:shibboleth:arp:matchFunction:regexMatch\">.*\\.example\\.edu</Requester>"
				+ "					<AnyResource />"
				+ "				</Target>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonAffiliation\">"
				+ "					<Value release=\"deny\">faculty@example.edu</Value>"
				+ "				</Attribute>"
				+ "				<Attribute name=\"urn:mace:eduPerson:1.0:eduPersonEntitlement\">"
				+ "					<Value release=\"permit\">urn:example:lovesIceCream</Value>"
				+ "				</Attribute>"
				+ "			</Rule>"
				+ "	</AttributeReleasePolicy>";

		Principal principal1 = new AuthNPrincipal("TestPrincipal");
		URL url1 = new URL("http://www.external.com/");

		AAAttributeSet inputSet =
			new AAAttributeSet(
				new AAAttribute[] {
					new AAAttribute(
						"urn:mace:eduPerson:1.0:eduPersonEntitlement",
						new Object[] {
							"urn:example:lovesIceCream",
							"urn:example:poorlyDressed",
							"urn:example:contract:113455",
							"urn:example:contract:4657483" }),
					new AAAttribute(
						"urn:mace:eduPerson:1.0:eduPersonAffiliation",
						new Object[] { "member@example.edu", "faculty@example.edu", "employee@example.edu" }),
					new AAAttribute(
						"urn:mace:eduPerson:1.0:eduPersonPrincipalName",
						new Object[] { "wassa@example.edu" }),
					new AAAttribute("urn:mace:inetOrgPerson:preferredLanguage", new Object[] { "EO" })
		});

		AAAttributeSet releaseSet =
			new AAAttributeSet(
				new AAAttribute[] {
					new AAAttribute(
						"urn:mace:eduPerson:1.0:eduPersonEntitlement",
						new Object[] { "urn:example:contract:113455" }),
					new AAAttribute(
						"urn:mace:eduPerson:1.0:eduPersonAffiliation",
						new Object[] { "member@example.edu" }),
					new AAAttribute("urn:mace:inetOrgPerson:preferredLanguage", new Object[] { "EO" })
		});

		//Add the site ARP
		parser.parse(new InputSource(new StringReader(rawSiteArp)));
		Arp siteArp = new Arp();
		siteArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(siteArp);

		//Add the user ARP
		parser.parse(new InputSource(new StringReader(rawUserArp)));
		Arp userArp = new Arp();
		userArp.setPrincipal(principal1);
		userArp.marshall(parser.getDocument().getDocumentElement());
		repository.update(userArp);

		ArpEngine engine = new ArpEngine(repository, props);

		//Apply the ARP
		engine.filterAttributes(inputSet, principal1, "www.external.com", url1);

		assertEquals("ARP application test 21: ARP not applied as expected.", inputSet, releaseSet);
	}

}
