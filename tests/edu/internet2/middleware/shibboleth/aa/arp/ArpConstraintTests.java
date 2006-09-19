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

import java.io.StringReader;
import java.net.URI;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import edu.internet2.middleware.shibboleth.aa.AAAttribute;
import edu.internet2.middleware.shibboleth.common.LocalPrincipal;
import edu.internet2.middleware.shibboleth.idp.IdPConfig;

/**
 * Validation suite for <code>Arp</code> Constraint processing.
 * 
 * @author Will Norris(wnorris@usc.edu)
 */

public class ArpConstraintTests extends TestCase {

	Logger log = Logger.getLogger(ArpConstraintTests.class);
	private Element memoryRepositoryElement;
	private ArpRepository repository;

	public ArpConstraintTests(String name) {

		super(name);
		BasicConfigurator.resetConfiguration();
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
		Logger.getLogger(ArpConstraintTests.class).setLevel(Level.DEBUG);
		Logger.getLogger(Rule.class).setLevel(Level.DEBUG);
	}

	public static void main(String[] args) {

		junit.textui.TestRunner.run(ArpConstraintTests.class);
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

		try {
			repository = ArpRepositoryFactory.getInstance(memoryRepositoryElement);
		} catch (ArpRepositoryException e) {
			fail("Failed to create memory-based Arp Repository" + e);
		}
	}

	/**
	 * test to ensure that attributes needed for constraints are included when listing possible attributes
	 */
	public void testConstraintAttributeSetComputation() {

		try {
			Principal principal1 = new LocalPrincipal("TestPrincipal");

			Collection<URI> expectedAttributes = new HashSet<URI>();
			expectedAttributes.add(new URI("urn:mace:dir:attribute-def:foo"));

			String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
					+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
					+ "         <Rule>"
					+ "             <Constraint attributeName=\"urn:mace:dir:attribute-def:foo\" matchFunction=\"urn:mace:shibboleth:arp:matchFunction:anyValueMatch\" />"
					+ "             <Target>" 
					+ "                 <AnyTarget/>" 
					+ "             </Target>"
					+ "             <Attribute name=\"urn:mace:dir:attribute-def:uid\">"
					+ "                 <AnyValue release=\"permit\"/>" 
					+ "             </Attribute>"
					+ "         </Rule>" 
					+ " </AttributeReleasePolicy>";

			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(true);
			Document doc = factory.newDocumentBuilder().parse(new InputSource(new StringReader(rawArp)));

			Arp arp1 = new Arp();
			arp1.marshall(doc.getDocumentElement());
			repository.update(arp1);
			ArpEngine engine = new ArpEngine(repository);
			Collection<URI> possibleAttributes = engine.listPossibleReleaseAttributes(principal1, "shar.example.edu");

			Collection<URI> constraintAttributes = engine.listRequiredConstraintAttributes(principal1,
					"shar.example.edu", possibleAttributes);

			assertEquals("Incorrectly computed constraint release set.", expectedAttributes, constraintAttributes);

		} catch (Exception e) {
			e.printStackTrace();
			fail("Failed to marshall ARP: " + e);
		}

	}

	/**
	 * Use Case: must have an attribute Logical expression: P (no specific value) Example: release uid only if user has
	 * attribute "foo"
	 */
	public void testArpConstraint1() throws Exception {

		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "         <Rule>"
				+ "             <Constraint attributeName=\"urn:mace:dir:attribute-def:foo\" matchFunction=\"urn:mace:shibboleth:arp:matchFunction:anyValueMatch\" />"
				+ "             <Target>" 
				+ "                 <AnyTarget/>" 
				+ "             </Target>"
				+ "             <Attribute name=\"urn:mace:dir:attribute-def:uid\">"
				+ "                 <AnyValue release=\"permit\"/>" 
				+ "             </Attribute>" 
				+ "         </Rule>"
				+ " </AttributeReleasePolicy>";

		// Setup the engine
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setValidating(false);
		factory.setNamespaceAware(true);
		Document doc = factory.newDocumentBuilder().parse(new InputSource(new StringReader(rawArp)));
		
		Arp siteArp = new Arp();
		siteArp.marshall(doc.getDocumentElement());
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
	 * Use Case: must not have an attribute Logical expression: not P Example: release uid only if user does not have
	 * attribute "foo"
	 */
	public void testArpConstraint2() throws Exception {

		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "         <Rule>" 
				+ "             <Constraint"
				+ "					attributeName=\"urn:mace:dir:attribute-def:foo\""
				+ "					matchFunction=\"urn:mace:shibboleth:arp:matchFunction:anyValueMatch\""
				+ "					matches=\"none\" />" 
				+ "             <Target>" 
				+ "                 <AnyTarget/>"
				+ "             </Target>" 
				+ "             <Attribute name=\"urn:mace:dir:attribute-def:uid\">"
				+ "                 <AnyValue release=\"permit\"/>" 
				+ "             </Attribute>" 
				+ "         </Rule>"
				+ " </AttributeReleasePolicy>";

		// Setup the engine
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setValidating(false);
		factory.setNamespaceAware(true);
		Document doc = factory.newDocumentBuilder().parse(new InputSource(new StringReader(rawArp)));
		
		Arp siteArp = new Arp();
		siteArp.marshall(doc.getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		Principal principal = new LocalPrincipal("TestPrincipal");

		// test user who meets constraint
		Collection<AAAttribute> inputSet1 = new ArrayList<AAAttribute>();
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		Collection<AAAttribute> releaseSet1 = new ArrayList<AAAttribute>();
		releaseSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		engine.filterAttributes(inputSet1, principal, "shar.example.edu");
		assertEquals("ARP application test 2a: ARP not applied as expected.", releaseSet1, inputSet1);

		// test user who does not meet constraint
		Collection<AAAttribute> inputSet2 = new ArrayList<AAAttribute>();
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:foo", new Object[]{"bar"}));

		Collection<AAAttribute> releaseSet2 = new ArrayList<AAAttribute>();

		engine.filterAttributes(inputSet2, principal, "shar.example.edu");
		assertEquals("ARP application test 2b: ARP not applied as expected.", releaseSet2, inputSet2);

	}

	/**
	 * Use Case: must have a specific attribute value Logical expression: Px (specific value) Example: release uid only
	 * if user has affiliation "member"
	 */
	public void testArpConstraint3() throws Exception {

		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "         <Rule>"
				+ "             <Constraint attributeName=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">member</Constraint>"
				+ "             <Target>" 
				+ "                 <AnyTarget/>" 
				+ "             </Target>"
				+ "             <Attribute name=\"urn:mace:dir:attribute-def:uid\">"
				+ "                 <AnyValue release=\"permit\"/>" 
				+ "             </Attribute>" 
				+ "         </Rule>"
				+ " </AttributeReleasePolicy>";

		// Setup the engine
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setValidating(false);
		factory.setNamespaceAware(true);
		Document doc = factory.newDocumentBuilder().parse(new InputSource(new StringReader(rawArp)));
		
		Arp siteArp = new Arp();
		siteArp.marshall(doc.getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		Principal principal = new LocalPrincipal("TestPrincipal");

		// test user who meets constraint
		Collection<AAAttribute> inputSet1 = new ArrayList<AAAttribute>();
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member"}));

		Collection<AAAttribute> releaseSet1 = new ArrayList<AAAttribute>();
		releaseSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		engine.filterAttributes(inputSet1, principal, "shar.example.edu");
		assertEquals("ARP application test 3a: ARP not applied as expected.", releaseSet1, inputSet1);

		// test user who does not meet constraint
		Collection<AAAttribute> inputSet2 = new ArrayList<AAAttribute>();
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"student"}));

		Collection<AAAttribute> releaseSet2 = new ArrayList<AAAttribute>();

		engine.filterAttributes(inputSet2, principal, "shar.example.edu");
		assertEquals("ARP application test 3b: ARP not applied as expected.", releaseSet2, inputSet2);

	}

	/**
	 * Use Case: must have an attribute value that matches a regular expression Logical expression: Pe (regular
	 * expression) Example: release uid only if user has scoped affiliation matching the regular expression
	 * ".*\@example\.edu"
	 */
	public void testArpConstraint4() throws Exception {

		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "         <Rule>" + "             <Constraint"
				+ "					attributeName=\"urn:mace:dir:attribute-def:eduPersonScopedAffiliation\""
				+ "					matchFunction=\"urn:mace:shibboleth:arp:matchFunction:regexMatch\""
				+ "					matches=\"any\">.*@example\\.edu</Constraint>" 
				+ "             <Target>"
				+ "                 <AnyTarget/>" 
				+ "             </Target>"
				+ "             <Attribute name=\"urn:mace:dir:attribute-def:uid\">"
				+ "                 <AnyValue release=\"permit\"/>" 
				+ "             </Attribute>" 
				+ "         </Rule>"
				+ " </AttributeReleasePolicy>";

		// Setup the engine
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setValidating(false);
		factory.setNamespaceAware(true);
		Document doc = factory.newDocumentBuilder().parse(new InputSource(new StringReader(rawArp)));
		
		Arp siteArp = new Arp();
		siteArp.marshall(doc.getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		Principal principal = new LocalPrincipal("TestPrincipal");

		// test user who meets constraint
		Collection<AAAttribute> inputSet1 = new ArrayList<AAAttribute>();
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonScopedAffiliation",
				new Object[]{"member@example.edu"}));

		Collection<AAAttribute> releaseSet1 = new ArrayList<AAAttribute>();
		releaseSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		engine.filterAttributes(inputSet1, principal, "shar.example.edu");
		assertEquals("ARP application test 4a: ARP not applied as expected.", releaseSet1, inputSet1);

		// test user who does not meet constraint
		Collection<AAAttribute> inputSet2 = new ArrayList<AAAttribute>();
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonScopedAffiliation",
				new Object[]{"member@testshib.org"}));

		Collection<AAAttribute> releaseSet2 = new ArrayList<AAAttribute>();

		engine.filterAttributes(inputSet2, principal, "shar.example.edu");
		assertEquals("ARP application test 4b: ARP not applied as expected.", releaseSet2, inputSet2);

	}

	/**
	 * Use Case: must not have a specific attribute value Logical expression: not Px Example: release uid only if user
	 * does not have affiliation "student" (lack of attribute is permitted)
	 */
	public void testArpConstraint5() throws Exception {

		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "         <Rule>" 
				+ "             <Constraint"
				+ "					attributeName=\"urn:mace:dir:attribute-def:eduPersonAffiliation\""
				+ "					matches=\"none\">student</Constraint>" 
				+ "             <Target>"
				+ "                 <AnyTarget/>" 
				+ "             </Target>"
				+ "             <Attribute name=\"urn:mace:dir:attribute-def:uid\">"
				+ "                 <AnyValue release=\"permit\"/>" 
				+ "             </Attribute>" 
				+ "         </Rule>"
				+ " </AttributeReleasePolicy>";

		// Setup the engine
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setValidating(false);
		factory.setNamespaceAware(true);
		Document doc = factory.newDocumentBuilder().parse(new InputSource(new StringReader(rawArp)));
		
		Arp siteArp = new Arp();
		siteArp.marshall(doc.getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		Principal principal = new LocalPrincipal("TestPrincipal");

		// test user who meets constraint
		Collection<AAAttribute> inputSet1 = new ArrayList<AAAttribute>();
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"staff"}));

		Collection<AAAttribute> releaseSet1 = new ArrayList<AAAttribute>();
		releaseSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		engine.filterAttributes(inputSet1, principal, "shar.example.edu");
		assertEquals("ARP application test 5a: ARP not applied as expected.", releaseSet1, inputSet1);

		// test another user who meets constraint
		Collection<AAAttribute> inputSet2 = new ArrayList<AAAttribute>();
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		Collection<AAAttribute> releaseSet2 = new ArrayList<AAAttribute>();
		releaseSet2.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		engine.filterAttributes(inputSet2, principal, "shar.example.edu");
		assertEquals("ARP application test 5b: ARP not applied as expected.", releaseSet2, inputSet2);

		// test user who does not meet constraint
		Collection<AAAttribute> inputSet3 = new ArrayList<AAAttribute>();
		inputSet3.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet3.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"staff",
				"student"}));

		Collection<AAAttribute> releaseSet3 = new ArrayList<AAAttribute>();

		engine.filterAttributes(inputSet3, principal, "shar.example.edu");
		assertEquals("ARP application test 5c: ARP not applied as expected.", releaseSet3, inputSet3);

	}

	/**
	 * Use case: must have at least one of multiple attribute values Logical expression: Px or Py Example: release uid
	 * only if user has affiliation of "faculty" or "staff"
	 */
	public void testArpConstraint6() throws Exception {

		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "         <Rule>" 
				+ "             <Constraint"
				+ "					attributeName=\"urn:mace:dir:attribute-def:eduPersonAffiliation\""
				+ "					matchFunction=\"urn:mace:shibboleth:arp:matchFunction:regexMatch\""
				+ "					matches=\"any\">(faculty|staff)</Constraint>" 
				+ "             <Target>"
				+ "                 <AnyTarget/>" 
				+ "             </Target>"
				+ "             <Attribute name=\"urn:mace:dir:attribute-def:uid\">"
				+ "                 <AnyValue release=\"permit\"/>" 
				+ "             </Attribute>" 
				+ "         </Rule>"
				+ " </AttributeReleasePolicy>";

		// Setup the engine
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setValidating(false);
		factory.setNamespaceAware(true);
		Document doc = factory.newDocumentBuilder().parse(new InputSource(new StringReader(rawArp)));
		
		Arp siteArp = new Arp();
		siteArp.marshall(doc.getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		Principal principal = new LocalPrincipal("TestPrincipal");

		// test user who meets constraint
		Collection<AAAttribute> inputSet1 = new ArrayList<AAAttribute>();
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"faculty"}));

		Collection<AAAttribute> releaseSet1 = new ArrayList<AAAttribute>();
		releaseSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		engine.filterAttributes(inputSet1, principal, "shar.example.edu");
		assertEquals("ARP application test 6a: ARP not applied as expected.", releaseSet1, inputSet1);

		// test user who does not meet constraint
		Collection<AAAttribute> inputSet2 = new ArrayList<AAAttribute>();
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"student"}));

		Collection<AAAttribute> releaseSet2 = new ArrayList<AAAttribute>();

		engine.filterAttributes(inputSet2, principal, "shar.example.edu");
		assertEquals("ARP application test 6b: ARP not applied as expected.", releaseSet2, inputSet2);

	}

	/**
	 * Use case: must have multiple specific values for the same attribute Logical expression: Px and Py Example:
	 * release uid only if user has entitlements "urn:x:foo" and "urn:x:bar"
	 */
	public void testArpConstraint7() throws Exception {

		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "         <Rule>"
				+ "             <Constraint attributeName=\"urn:mace:dir:attribute-def:eduPersonEntitlement\">urn:x:foo</Constraint>"
				+ "             <Constraint attributeName=\"urn:mace:dir:attribute-def:eduPersonEntitlement\">urn:x:bar</Constraint>"
				+ "             <Target>" 
				+ "                 <AnyTarget/>" 
				+ "             </Target>"
				+ "             <Attribute name=\"urn:mace:dir:attribute-def:uid\">"
				+ "                 <AnyValue release=\"permit\"/>" 
				+ "             </Attribute>" 
				+ "         </Rule>"
				+ " </AttributeReleasePolicy>";

		// Setup the engine
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setValidating(false);
		factory.setNamespaceAware(true);
		Document doc = factory.newDocumentBuilder().parse(new InputSource(new StringReader(rawArp)));
		
		Arp siteArp = new Arp();
		siteArp.marshall(doc.getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		Principal principal = new LocalPrincipal("TestPrincipal");

		// test user who meets constraint
		Collection<AAAttribute> inputSet1 = new ArrayList<AAAttribute>();
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonEntitlement", new Object[]{"urn:x:foo",
				"urn:x:bar"}));

		Collection<AAAttribute> releaseSet1 = new ArrayList<AAAttribute>();
		releaseSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		engine.filterAttributes(inputSet1, principal, "shar.example.edu");
		assertEquals("ARP application test 7a: ARP not applied as expected.", releaseSet1, inputSet1);

		// test user who does not meet constraint
		Collection<AAAttribute> inputSet2 = new ArrayList<AAAttribute>();
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonEntitlement", new Object[]{"urn:x:foo"}));

		Collection<AAAttribute> releaseSet2 = new ArrayList<AAAttribute>();

		engine.filterAttributes(inputSet2, principal, "shar.example.edu");
		assertEquals("ARP application test 7b: ARP not applied as expected.", releaseSet2, inputSet2);

	}

	/**
	 * Use case: must have one specific attribute value, but cannot have another Logical expression: Px and not Py
	 * Example: release uid for all users who have an affilation of "staff" AND do not have an affiliation of "student"
	 */
	public void testArpConstraint8() throws Exception {

		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "         <Rule>"
				+ "             <Constraint attributeName=\"urn:mace:dir:attribute-def:eduPersonAffiliation\" matches=\"any\">staff</Constraint>"
				+ "             <Constraint attributeName=\"urn:mace:dir:attribute-def:eduPersonAffiliation\" matches=\"none\">student</Constraint>"
				+ "             <Target>" 
				+ "                 <AnyTarget/>" 
				+ "             </Target>"
				+ "             <Attribute name=\"urn:mace:dir:attribute-def:uid\">"
				+ "                 <AnyValue release=\"permit\"/>" 
				+ "             </Attribute>" 
				+ "         </Rule>"
				+ " </AttributeReleasePolicy>";

		// Setup the engine
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setValidating(false);
		factory.setNamespaceAware(true);
		Document doc = factory.newDocumentBuilder().parse(new InputSource(new StringReader(rawArp)));
		
		Arp siteArp = new Arp();
		siteArp.marshall(doc.getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		Principal principal = new LocalPrincipal("TestPrincipal");

		// test user who meets constraint
		Collection<AAAttribute> inputSet1 = new ArrayList<AAAttribute>();
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"staff",
				"faculty"}));

		Collection<AAAttribute> releaseSet1 = new ArrayList<AAAttribute>();
		releaseSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		engine.filterAttributes(inputSet1, principal, "shar.example.edu");
		assertEquals("ARP application test 8a: ARP not applied as expected.", releaseSet1, inputSet1);

		// test user who does not meet constraint
		Collection<AAAttribute> inputSet2 = new ArrayList<AAAttribute>();
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"staff",
				"student"}));

		Collection<AAAttribute> releaseSet2 = new ArrayList<AAAttribute>();

		engine.filterAttributes(inputSet2, principal, "shar.example.edu");
		assertEquals("ARP application test 8b: ARP not applied as expected.", releaseSet2, inputSet2);

	}

	/**
	 * Use case: must have an attribute value, but deny a specific one Logical expression: P and not Px Example: release
	 * uid for all users who have an affiliation (any value), but not for those that have an affiliation of "student"
	 * (lack of attribute is denied)
	 */
	public void testArpConstraint9() throws Exception {

		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "         <Rule>" 
				+ "             <Constraint"
				+ "					attributeName=\"urn:mace:dir:attribute-def:eduPersonAffiliation\""
				+ "					matchFunction=\"urn:mace:shibboleth:arp:matchFunction:anyValueMatch\" />"
				+ "             <Constraint" 
				+ "					attributeName=\"urn:mace:dir:attribute-def:eduPersonAffiliation\""
				+ "					matches=\"none\">student</Constraint>" 
				+ "             <Target>"
				+ "                 <AnyTarget/>" 
				+ "             </Target>"
				+ "             <Attribute name=\"urn:mace:dir:attribute-def:uid\">"
				+ "                 <AnyValue release=\"permit\"/>" 
				+ "             </Attribute>" 
				+ "         </Rule>"
				+ " </AttributeReleasePolicy>";

		// Setup the engine
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setValidating(false);
		factory.setNamespaceAware(true);
		Document doc = factory.newDocumentBuilder().parse(new InputSource(new StringReader(rawArp)));
		
		Arp siteArp = new Arp();
		siteArp.marshall(doc.getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		Principal principal = new LocalPrincipal("TestPrincipal");

		// test user who meets constraint
		Collection<AAAttribute> inputSet1 = new ArrayList<AAAttribute>();
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"staff"}));

		Collection<AAAttribute> releaseSet1 = new ArrayList<AAAttribute>();
		releaseSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		engine.filterAttributes(inputSet1, principal, "shar.example.edu");
		assertEquals("ARP application test 9a: ARP not applied as expected.", releaseSet1, inputSet1);

		// test user who does not meet constraint
		Collection<AAAttribute> inputSet2 = new ArrayList<AAAttribute>();
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"staff",
				"student"}));

		Collection<AAAttribute> releaseSet2 = new ArrayList<AAAttribute>();

		engine.filterAttributes(inputSet2, principal, "shar.example.edu");
		assertEquals("ARP application test 9b: ARP not applied as expected.", releaseSet2, inputSet2);

		// test another user who does not meet constraint
		Collection<AAAttribute> inputSet3 = new ArrayList<AAAttribute>();
		inputSet3.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		Collection<AAAttribute> releaseSet3 = new ArrayList<AAAttribute>();

		engine.filterAttributes(inputSet3, principal, "shar.example.edu");
		assertEquals("ARP application test 9c: ARP not applied as expected.", releaseSet3, inputSet3);

	}

	/**
	 * Use case: must have specific values for two separate attributes Logical expression: Px and Qy Example: release
	 * uid only if user has entitlement "urn:x:foo" and has affiliation of "faculty"
	 */
	public void testArpConstraint10() throws Exception {

		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "         <Rule>"
				+ "             <Constraint attributeName=\"urn:mace:dir:attribute-def:eduPersonEntitlement\">urn:x:foo</Constraint>"
				+ "             <Constraint attributeName=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">faculty</Constraint>"
				+ "             <Target>" 
				+ "                 <AnyTarget/>" 
				+ "             </Target>"
				+ "             <Attribute name=\"urn:mace:dir:attribute-def:uid\">"
				+ "                 <AnyValue release=\"permit\"/>" 
				+ "             </Attribute>" 
				+ "         </Rule>"
				+ " </AttributeReleasePolicy>";

		// Setup the engine
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setValidating(false);
		factory.setNamespaceAware(true);
		Document doc = factory.newDocumentBuilder().parse(new InputSource(new StringReader(rawArp)));
		
		Arp siteArp = new Arp();
		siteArp.marshall(doc.getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		Principal principal = new LocalPrincipal("TestPrincipal");

		// test user who meets constraint
		Collection<AAAttribute> inputSet1 = new ArrayList<AAAttribute>();
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonEntitlement", new Object[]{"urn:x:foo"}));
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"staff",
				"faculty"}));

		Collection<AAAttribute> releaseSet1 = new ArrayList<AAAttribute>();
		releaseSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		engine.filterAttributes(inputSet1, principal, "shar.example.edu");
		assertEquals("ARP application test 10a: ARP not applied as expected.", releaseSet1, inputSet1);

		// test user who does not meet constraint
		Collection<AAAttribute> inputSet2 = new ArrayList<AAAttribute>();
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonEntitlement", new Object[]{"urn:x:foo"}));
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"staff",
				"student"}));

		Collection<AAAttribute> releaseSet2 = new ArrayList<AAAttribute>();

		engine.filterAttributes(inputSet2, principal, "shar.example.edu");
		assertEquals("ARP application test 10b: ARP not applied as expected.", releaseSet2, inputSet2);

	}

	/**
	 * Use case: must have one attribute value or not a value for another attribute Logical expression: Px or not Qy
	 * Example: release uid only if user has an affiliation of "staff" or if the user does not have isPrivate equal to
	 * "Y"
	 */
	public void testArpConstraint11() throws Exception {

		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "         <Rule>"
				+ "             <Constraint attributeName=\"urn:mace:dir:attribute-def:eduPersonAffiliation\">staff</Constraint>"
				+ "             <Target>"
				+ "                 <AnyTarget/>"
				+ "             </Target>"
				+ "             <Attribute name=\"urn:mace:dir:attribute-def:uid\">"
				+ "                 <AnyValue release=\"permit\"/>"
				+ "             </Attribute>"
				+ "         </Rule>"
				+ "         <Rule>"
				+ "             <Constraint attributeName=\"urn:mace:dir:attribute-def:isPrivate\" matches=\"none\">Y</Constraint>"
				+ "             <Target>" 
				+ "                 <AnyTarget/>" 
				+ "             </Target>"
				+ "             <Attribute name=\"urn:mace:dir:attribute-def:uid\">"
				+ "                 <AnyValue release=\"permit\"/>" 
				+ "             </Attribute>" 
				+ "         </Rule>"
				+ " </AttributeReleasePolicy>";

		// Setup the engine
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setValidating(false);
		factory.setNamespaceAware(true);
		Document doc = factory.newDocumentBuilder().parse(new InputSource(new StringReader(rawArp)));
		
		Arp siteArp = new Arp();
		siteArp.marshall(doc.getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		Principal principal = new LocalPrincipal("TestPrincipal");

		// test user who meets constraint
		Collection<AAAttribute> inputSet1 = new ArrayList<AAAttribute>();
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:isPrivate", new Object[]{"Y"}));
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"staff"}));

		Collection<AAAttribute> releaseSet1 = new ArrayList<AAAttribute>();
		releaseSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		engine.filterAttributes(inputSet1, principal, "shar.example.edu");
		assertEquals("ARP application test 11a: ARP not applied as expected.", releaseSet1, inputSet1);

		// test another user who meets constraint
		Collection<AAAttribute> inputSet2 = new ArrayList<AAAttribute>();
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:isPrivate", new Object[]{"N"}));
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"student"}));

		Collection<AAAttribute> releaseSet2 = new ArrayList<AAAttribute>();
		releaseSet2.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		engine.filterAttributes(inputSet2, principal, "shar.example.edu");
		assertEquals("ARP application test 11a: ARP not applied as expected.", releaseSet2, inputSet2);

		// test user who does not meet constraint
		Collection<AAAttribute> inputSet3 = new ArrayList<AAAttribute>();
		inputSet3.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet3.add(new AAAttribute("urn:mace:dir:attribute-def:isPrivate", new Object[]{"Y"}));
		inputSet3.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"student"}));

		Collection<AAAttribute> releaseSet3 = new ArrayList<AAAttribute>();

		engine.filterAttributes(inputSet3, principal, "shar.example.edu");
		assertEquals("ARP application test 11c: ARP not applied as expected.", releaseSet3, inputSet3);

	}

	/**
	 * Use case: release additional attributes for a subset of users Example: release targetedId for all users with
	 * entitlement "urn:x:foo". also release uid for users without ferpaSuppression
	 */
	public void testArpConstraint12() throws Exception {

		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "         <Rule>"
				+ "             <Constraint attributeName=\"urn:mace:dir:attribute-def:eduPersonEntitlement\">urn:x:foo</Constraint>"
				+ "             <Target>" 
				+ "                 <AnyTarget/>" 
				+ "             </Target>"
				+ "             <Attribute name=\"urn:mace:dir:attribute-def:eduPersonTargetedID\">"
				+ "                 <AnyValue release=\"permit\"/>" 
				+ "             </Attribute>" 
				+ "         </Rule>"
				+ "         <Rule>" 
				+ "             <Constraint"
				+ "					attributeName=\"urn:mace:dir:attribute-def:ferpaSuppression\""
				+ "					matchFunction=\"urn:mace:shibboleth:arp:matchFunction:anyValueMatch\""
				+ "					matches=\"none\" />" 
				+ "             <Target>" 
				+ "                 <AnyTarget/>"
				+ "             </Target>" 
				+ "             <Attribute name=\"urn:mace:dir:attribute-def:uid\">"
				+ "                 <AnyValue release=\"permit\"/>" 
				+ "             </Attribute>" 
				+ "         </Rule>"
				+ " </AttributeReleasePolicy>";

		// Setup the engine
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setValidating(false);
		factory.setNamespaceAware(true);
		Document doc = factory.newDocumentBuilder().parse(new InputSource(new StringReader(rawArp)));
		
		Arp siteArp = new Arp();
		siteArp.marshall(doc.getDocumentElement());
		repository.update(siteArp);
		ArpEngine engine = new ArpEngine(repository);

		Principal principal = new LocalPrincipal("TestPrincipal");

		// test user who meets constraint
		Collection<AAAttribute> inputSet1 = new ArrayList<AAAttribute>();
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonTargetedID",
				new Object[]{"2b00042f7481c7b056c4b410d28f33cf"}));
		inputSet1.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonEntitlement", new Object[]{"urn:x:foo"}));

		Collection<AAAttribute> releaseSet1 = new ArrayList<AAAttribute>();
		releaseSet1.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		releaseSet1.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonTargetedID",
				new Object[]{"2b00042f7481c7b056c4b410d28f33cf"}));

		engine.filterAttributes(inputSet1, principal, "shar.example.edu");
		assertEquals("ARP application test 12a: ARP not applied as expected.", releaseSet1, inputSet1);

		// test user who does not meet constraint
		Collection<AAAttribute> inputSet2 = new ArrayList<AAAttribute>();
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonTargetedID",
				new Object[]{"2b00042f7481c7b056c4b410d28f33cf"}));
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonEntitlement", new Object[]{"urn:x:foo"}));
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:ferpaSuppression", new Object[]{"2006-01-01"}));

		Collection<AAAttribute> releaseSet2 = new ArrayList<AAAttribute>();
		releaseSet2.add(new AAAttribute("urn:mace:dir:attribute-def:eduPersonTargetedID",
				new Object[]{"2b00042f7481c7b056c4b410d28f33cf"}));

		engine.filterAttributes(inputSet2, principal, "shar.example.edu");
		assertEquals("ARP application test 12b: ARP not applied as expected.", releaseSet2, inputSet2);

	}

	/**
	 * Use Case: must have only a specific attribute value Example: release uid only if user has a specific value for
	 * attribute "foo", but not if it has other values
	 */
	public void testArpConstraint13() throws Exception {

		String rawArp = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				+ "<AttributeReleasePolicy xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"urn:mace:shibboleth:arp:1.0\" xsi:schemaLocation=\"urn:mace:shibboleth:arp:1.0 shibboleth-arp-1.0.xsd\">"
				+ "         <Rule>" 
				+ "             <Constraint"
				+ "					attributeName=\"urn:mace:dir:attribute-def:foo\""
				+ "					matchFunction=\"urn:mace:shibboleth:arp:matchFunction:stringMatch\""
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
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setValidating(false);
		factory.setNamespaceAware(true);
		Document doc = factory.newDocumentBuilder().parse(new InputSource(new StringReader(rawArp)));
		
		Arp siteArp = new Arp();
		siteArp.marshall(doc.getDocumentElement());
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
		assertEquals("ARP application test 3a: ARP not applied as expected.", releaseSet1, inputSet1);

		// test user who does not meet constraint
		Collection<AAAttribute> inputSet2 = new ArrayList<AAAttribute>();
		inputSet2.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));

		Collection<AAAttribute> releaseSet2 = new ArrayList<AAAttribute>();

		engine.filterAttributes(inputSet2, principal, "shar.example.edu");
		assertEquals("ARP application test 3b: ARP not applied as expected.", releaseSet2, inputSet2);

		// test another user who does not meet constraint
		Collection<AAAttribute> inputSet3 = new ArrayList<AAAttribute>();
		inputSet3.add(new AAAttribute("urn:mace:dir:attribute-def:uid", new Object[]{"gpburdell"}));
		inputSet3.add(new AAAttribute("urn:mace:dir:attribute-def:foo", new Object[]{"bar"}));
		inputSet3.add(new AAAttribute("urn:mace:dir:attribute-def:foo", new Object[]{"baz"}));

		Collection<AAAttribute> releaseSet3 = new ArrayList<AAAttribute>();

		engine.filterAttributes(inputSet3, principal, "shar.example.edu");
		assertEquals("ARP application test 3c: ARP not applied as expected.", releaseSet3, inputSet3);

	}
}
