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

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Properties;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.xerces.parsers.DOMParser;
import org.xml.sax.InputSource;

/**
 * Validation suite for <code>Arp</code> processing.
 * 
 * @ author Walter Hoehn(wassa@columbia.edu)
 */

public class ArpTests extends TestCase {

	public ArpTests(String name) {
		super(name);
		BasicConfigurator.configure();
	}

	public static void main(String[] args) {
		junit.textui.TestRunner.run(ArpTests.class);
		BasicConfigurator.configure();
	}

	public void testArpMarshalling() {

		//Test ARP description
		try {
			InputStream inStream = new FileInputStream("test/arp1.xml");
			DOMParser parser = new DOMParser();
			parser.parse(new InputSource(inStream));
			Arp arp1 = new Arp();
			arp1.marshall(parser.getDocument().getDocumentElement());
			assertEquals(
				"ARP Description not marshalled properly",
				arp1.getDescription(),
				"Simplest possible ARP.");

			//Test Rule description
			assertEquals(
				"ARP Rule Description not marshalled properly",
				arp1.getAllRules()[0].getDescription(),
				"Example Rule Description.");
		} catch (Exception e) {
			fail("Failed to marshall ARP.");
		}

		//Test case where ARP description does not exist
		try {
			InputStream inStream = new FileInputStream("test/arp2.xml");
			DOMParser parser = new DOMParser();
			parser.parse(new InputSource(inStream));
			Arp arp2 = new Arp();
			arp2.marshall(parser.getDocument().getDocumentElement());
			assertNull("ARP Description not marshalled properly", arp2.getDescription());

			//Test case where ARP Rule description does not exist	
			assertNull(
				"ARP Rule Description not marshalled properly",
				arp2.getAllRules()[0].getDescription());
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
			assertNotNull(
				"ArpEngine did not properly load the Resource Tree SHAR function.",
				resourceTreeFunction);

			/* 
			 * Test the Exact SHAR function
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
			 * Test the Resource Tree function
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
				resourceTreeFunction.match(
					"http://www.example.edu/test2/index.html?test1=test1",
					requestURL4));
			assertTrue(
				"Resource Tree function: false positive",
				!resourceTreeFunction.match(
					"http://www.example.edu/test2/index.html?test1=test1",
					requestURL3));

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

		Arp userArp2 = new Arp(new AAPrincipal("TestPrincipal"));
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

	}

}
