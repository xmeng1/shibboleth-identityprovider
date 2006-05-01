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

package edu.internet2.middleware.shibboleth.aa.attrresolv;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.opensaml.SAMLException;

import edu.internet2.middleware.shibboleth.aa.AAAttribute;
import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.ScopedStringValueHandler;
import edu.internet2.middleware.shibboleth.common.LocalPrincipal;

/**
 * Validation suite for the <code>AttributeResolver</code>.
 * 
 * @author Walter Hoehn(wassa@columbia.edu)
 * @author Vishal Goenka
 */

public class ResolverTests extends TestCase {

	// Simple explanatory booleans, which are helpful when passed in functions as compared to true/false
	private static final boolean DO_SORT = true;
	private static final boolean DO_NOT_SORT = false;

	public ResolverTests(String name) {

		super(name);
		BasicConfigurator.resetConfiguration();
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	public static void main(String[] args) {

		junit.textui.TestRunner.run(ResolverTests.class);
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	/**
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {

		super.setUp();
	}

	public void testBasic() {

		try {
			File file = new File("data/resolver1.xml");
			AttributeResolver ar = new AttributeResolver(file.toURL().toString());

			Map<String, ResolverAttribute> inputAttributes = new HashMap<String, ResolverAttribute>();
			AAAttribute one = new AAAttribute("urn:mace:dir:attribute-def:eduPersonNickName");
			inputAttributes.put(one.getName(), one);
			AAAttribute two = new AAAttribute("urn:mace:dir:attribute-def:eduPersonEntitlement");
			inputAttributes.put(two.getName(), two);

			Map<String, ResolverAttribute> outputAttributes = new HashMap<String, ResolverAttribute>();
			AAAttribute three = new AAAttribute("urn:mace:dir:attribute-def:eduPersonEntitlement",
					new Object[]{"urn:mace:example.edu:exampleEntitlement"});
			outputAttributes.put(three.getName(), three);

			ar.resolveAttributes(new LocalPrincipal("mytestuser"), "shar.example.edu", null, inputAttributes);

			assertEquals("Attribute Resolver returned unexpected attribute set.", inputAttributes, outputAttributes);

		} catch (AttributeResolverException e) {
			fail("Couldn't load attribute resolver: " + e.getMessage());
		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (SAMLException e) {
			fail("Error creating SAML Attribute: " + e.getMessage());
		}
	}

	public void testSmartScoping() {

		try {

			File file = new File("data/resolver2.xml");
			AttributeResolver ar = new AttributeResolver(file.toURL().toString());

			HashMap<String, ResolverAttribute> inputAttributes = new HashMap<String, ResolverAttribute>();
			AAAttribute one = new AAAttribute("urn:mace:dir:attribute-def:eduPersonPrincipalName");
			inputAttributes.put(one.getName(), one);
			AAAttribute two = new AAAttribute("foo");
			inputAttributes.put(two.getName(), two);

			HashMap<String, ResolverAttribute> outputAttributes = new HashMap<String, ResolverAttribute>();
			// Attribute should have scope appended to connector output
			AAAttribute three = new AAAttribute("urn:mace:dir:attribute-def:eduPersonPrincipalName",
					new Object[]{"mytestuser@example.edu"}, new ScopedStringValueHandler("example.edu"));
			outputAttributes.put(three.getName(), three);
			// Attribute should retain scope from connector output
			AAAttribute four = new AAAttribute("foo", new Object[]{"bar@example.com"}, new ScopedStringValueHandler(
					"example.edu"));
			outputAttributes.put(four.getName(), four);

			ar.resolveAttributes(new LocalPrincipal("mytestuser"), "shar.example.edu", null, inputAttributes);
			assertEquals("Attribute Resolver returned unexpected attribute set.", inputAttributes, outputAttributes);

		} catch (AttributeResolverException e) {
			fail("Couldn't load attribute resolver: " + e.getMessage());
		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (SAMLException e) {
			fail("Error creating SAML Attribute: " + e.getMessage());
		}
	}

	public void testExceptionForNoPlugIns() {

		try {
			File file = new File("data/resolver3.xml");
			new AttributeResolver(file.toURL().toString());

			fail("Attribute Resolver loaded even when no PlugIns were configured.");
		} catch (AttributeResolverException e) {
			// This exception should be thrown, ignoring
		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		}
	}

	public void testExceptionForNoValidPlugIns() {

		try {
			File file = new File("data/resolver4.xml");
			new AttributeResolver(file.toURL().toString());
			fail("Attribute Resolver loaded even when no PlugIns were successfully registered.");
		} catch (AttributeResolverException e) {
			// This exception should be thrown, ignoring
		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		}
	}

	public void testFailToLoadCircularDependencies() {

		try {
			File file = new File("data/resolver5.xml");
			new AttributeResolver(file.toURL().toString());
			fail("Attribute Resolver loaded even when no only PlugIns with circular dependencies were configured.");
		} catch (AttributeResolverException e) {
			// This exception should be thrown, ignoring
		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		}
	}

	public void testFailToLoadCircularDependenciesDeeper() {

		try {
			File file = new File("data/resolver6.xml");
			new AttributeResolver(file.toURL().toString());
			fail("Attribute Resolver loaded even when no only PlugIns with circular dependencies were configured.");
		} catch (AttributeResolverException e) {
			// This exception should be thrown, ignoring
		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		}
	}

	public void testSourceNameMapping() {

		try {
			File file = new File("data/resolver7.xml");
			AttributeResolver ar = new AttributeResolver(file.toURL().toString());

			HashMap<String, ResolverAttribute> inputAttributes = new HashMap<String, ResolverAttribute>();

			AAAttribute one = new AAAttribute("myAffiliation");
			inputAttributes.put(one.getName(), one);

			HashMap<String, ResolverAttribute> outputAttributes = new HashMap<String, ResolverAttribute>();
			AAAttribute two = new AAAttribute("myAffiliation", new Object[]{"member"});
			outputAttributes.put(two.getName(), two);

			ar.resolveAttributes(new LocalPrincipal("mytestuser"), "shar.example.edu", null, inputAttributes);
			assertEquals("Attribute Resolver returned unexpected attribute set.", inputAttributes, outputAttributes);

		} catch (AttributeResolverException e) {
			fail("Couldn't load attribute resolver: " + e.getMessage());
		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (SAMLException e) {
			fail("Error creating SAML Attribute: " + e.getMessage());
		}
	}

	public void testMultipleDataConnectors() {

		try {
			File file = new File("data/resolver8.xml");
			AttributeResolver ar = new AttributeResolver(file.toURL().toString());

			HashMap<String, ResolverAttribute> inputAttributes = new HashMap<String, ResolverAttribute>();
			AAAttribute one = new AAAttribute("urn:mace:dir:attribute-def:eduPersonPrincipalName");
			inputAttributes.put(one.getName(), one);
			AAAttribute two = new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation");
			inputAttributes.put(two.getName(), two);
			AAAttribute three = new AAAttribute("urn:mace:dir:attribute-def:eduPersonEntitlement");
			inputAttributes.put(three.getName(), three);

			HashMap<String, ResolverAttribute> outputAttributes = new HashMap<String, ResolverAttribute>();
			AAAttribute four = new AAAttribute("urn:mace:dir:attribute-def:eduPersonPrincipalName",
					new Object[]{"mytestuser@example.edu"}, new ScopedStringValueHandler("example.edu"));
			outputAttributes.put(four.getName(), four);
			AAAttribute five = new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation",
					new Object[]{"member"});
			outputAttributes.put(five.getName(), five);
			AAAttribute six = new AAAttribute("urn:mace:dir:attribute-def:eduPersonEntitlement",
					new Object[]{"urn:mace:example.edu:exampleEntitlement"});
			outputAttributes.put(six.getName(), six);

			ar.resolveAttributes(new LocalPrincipal("mytestuser"), "shar.example.edu", null, inputAttributes);

			assertEquals("Attribute Resolver returned unexpected attribute set.", inputAttributes, outputAttributes);

		} catch (AttributeResolverException e) {
			fail("Couldn't load attribute resolver: " + e.getMessage());
		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (SAMLException e) {
			fail("Error creating SAML Attribute: " + e.getMessage());
		}
	}

	public void testAttributeDependency() {

		try {
			File file = new File("data/resolver9.xml");
			AttributeResolver ar = new AttributeResolver(file.toURL().toString());

			HashMap<String, ResolverAttribute> inputAttributes = new HashMap<String, ResolverAttribute>();
			AAAttribute one = new AAAttribute("urn:mace:dir:attribute-def:eduPersonScopedAffiliation");
			inputAttributes.put(one.getName(), one);

			HashMap<String, ResolverAttribute> outputAttributes = new HashMap<String, ResolverAttribute>();
			AAAttribute two = new AAAttribute("urn:mace:dir:attribute-def:eduPersonScopedAffiliation",
					new Object[]{"member@example.edu"}, new ScopedStringValueHandler("example.edu"));
			outputAttributes.put(two.getName(), two);

			ar.resolveAttributes(new LocalPrincipal("mytestuser"), "shar.example.edu", null, inputAttributes);

			assertEquals("Attribute Resolver returned unexpected attribute set.", inputAttributes, outputAttributes);

		} catch (AttributeResolverException e) {
			fail("Couldn't load attribute resolver: " + e.getMessage());
		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (SAMLException e) {
			fail("Error creating SAML Attribute: " + e.getMessage());
		}
	}

	public void testMisLabeledDataConnector() {

		try {
			File file = new File("data/resolver11.xml");
			AttributeResolver ar = new AttributeResolver(file.toURL().toString());

			HashMap<String, ResolverAttribute> inputAttributes = new HashMap<String, ResolverAttribute>();
			AAAttribute one = new AAAttribute("urn:mace:dir:attribute-def:eduPersonScopedAffiliation");
			inputAttributes.put(one.getName(), one);

			HashMap<String, ResolverAttribute> outputAttributes = new HashMap<String, ResolverAttribute>();

			ar.resolveAttributes(new LocalPrincipal("mytestuser"), "shar.example.edu", null, inputAttributes);

			assertEquals("Attribute Resolver returned unexpected attribute set.", inputAttributes, outputAttributes);

		} catch (AttributeResolverException e) {
			fail("Couldn't load attribute resolver: " + e.getMessage());
		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (SAMLException e) {
			fail("Error creating SAML Attribute: " + e.getMessage());
		}
	}

	public void testMisLabeledAttributeDefinition() {

		try {
			File file = new File("data/resolver10.xml");
			AttributeResolver ar = new AttributeResolver(file.toURL().toString());

			HashMap<String, ResolverAttribute> inputAttributes = new HashMap<String, ResolverAttribute>();
			AAAttribute one = new AAAttribute("urn:mace:dir:attribute-def:eduPersonScopedAffiliation");
			inputAttributes.put(one.getName(), one);

			HashMap<String, ResolverAttribute> outputAttributes = new HashMap<String, ResolverAttribute>();

			ar.resolveAttributes(new LocalPrincipal("mytestuser"), "shar.example.edu", null, inputAttributes);

			assertEquals("Attribute Resolver returned unexpected attribute set.", inputAttributes, outputAttributes);
		} catch (ClassCastException e) {
			fail("Failed to detect that an Attribute Definition was mislabeled as a Data Connector: " + e.getMessage());
		} catch (AttributeResolverException e) {
			fail("Couldn't load attribute resolver: " + e.getMessage());
		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (SAMLException e) {
			fail("Error creating SAML Attribute: " + e.getMessage());
		}
	}

	public void testMultiLevelAttributeDependency() {

		try {
			File file = new File("data/resolver12.xml");
			AttributeResolver ar = new AttributeResolver(file.toURL().toString());

			HashMap<String, ResolverAttribute> inputAttributes = new HashMap<String, ResolverAttribute>();

			AAAttribute one = new AAAttribute("urn:mace:dir:attribute-def:eduPersonScopedAffiliation");
			inputAttributes.put(one.getName(), one);
			AAAttribute two = new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation");
			inputAttributes.put(two.getName(), two);
			AAAttribute three = new AAAttribute("urn:mace:shibboleth:test:eduPersonAffiliation");
			inputAttributes.put(three.getName(), three);

			HashMap<String, ResolverAttribute> outputAttributes = new HashMap<String, ResolverAttribute>();
			AAAttribute four = new AAAttribute("urn:mace:dir:attribute-def:eduPersonScopedAffiliation",
					new Object[]{"member@example.edu"}, new ScopedStringValueHandler("example.edu"));
			outputAttributes.put(four.getName(), four);
			AAAttribute five = new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation",
					new Object[]{"member"});
			outputAttributes.put(five.getName(), five);
			AAAttribute six = new AAAttribute("urn:mace:shibboleth:test:eduPersonAffiliation", new Object[]{"member"});
			outputAttributes.put(six.getName(), six);

			ar.resolveAttributes(new LocalPrincipal("mytestuser"), "shar.example.edu", null, inputAttributes);

			assertEquals("Attribute Resolver returned unexpected attribute set.", inputAttributes, outputAttributes);

		} catch (AttributeResolverException e) {
			fail("Couldn't load attribute resolver: " + e.getMessage());
		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (SAMLException e) {
			fail("Error creating SAML Attribute: " + e.getMessage());
		}
	}

	/**
	 * This method is reused by several tests that use different XML files as test data.
	 * 
	 * @param resolverFile
	 *            filename of a file containing data in the same format as resolver.xml.
	 * @param attributeFile
	 *            filename of a file containing output of the attribute resolution. The input file for attribute
	 *            resolution is specified in the resolverFile itself
	 * @param principal
	 *            name of the principal on whose behalf the resolution is done
	 * @param requester
	 *            the Shibboleth Target SHAR that is requesting the attribute resolution
	 */

	private void simpleAttributeResolution(String resolverFile, String attributeFile, String principal,
			String requester, boolean sort) {

		try {
			// Create the attribute resolver
			File file = new File(resolverFile);
			AttributeResolver ar = new AttributeResolver(file.toURL().toString());

			// Create the output attributes file
			AttributesFile attrFile = new AttributesFile(attributeFile);

			// Read only the attribute names from the output file. The values are set by the resolver
			Map<String, AAAttribute> attrsToBeResolved = attrFile.getResolverAttributes(false);
			ar.resolveAttributes(new LocalPrincipal(principal), requester, null, attrsToBeResolved);

			// Read the attribute names and values from the output file
			Map<String, AAAttribute> expectedAttributes = attrFile.getResolverAttributes(true);

			if (sort) {
				sort(attrsToBeResolved);
				sort(expectedAttributes);
			}
			// Ensure that the values set by the resolver are the same as the ones outlined in the output file
			assertEquals("Attribute Resolver returned unexpected attribute set.", expectedAttributes, attrsToBeResolved);
		} catch (AttributeResolverException e) {
			fail("Couldn't load attribute resolver: " + e.getMessage());
		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (IOException e) {
			fail("Error in test data: " + e.getMessage());
		} catch (SAMLException e) {
			fail("Error creating SAML attribute: " + e.getMessage());
		}
	}

	public void testAttrDef_RegEx_DN_CN_UID() {

		simpleAttributeResolution("data/attr-regex.resolver.1.xml", "data/attr-regex.output.1", "RegExTestUser",
				"urn::test:luminis::sungardsct::com", DO_NOT_SORT);
	}

	public void testAttrDef_Mapped_PdsRole_EduPersonAffiliation() {

		simpleAttributeResolution("data/attr-mapped.resolver.1.xml", "data/attr-mapped.output.1", "MappedTestUser",
				"urn::test:luminis::sungardsct::com", DO_SORT);
	}

	public void testAttrDef_Mapped_Role_EduPersonEntitlement() {

		simpleAttributeResolution("data/attr-mapped.resolver.2.xml", "data/attr-mapped.output.2", "MappedTestUser",
				"urn::test:luminis::sungardsct::com", DO_SORT);
	}

	public void testAttrDef_Formatted_DateOfBirth() {

		simpleAttributeResolution("data/attr-format.resolver.1.xml", "data/attr-format.output.1",
				"FormattedDateTestUser", "urn::test:luminis::sungardsct::com", DO_NOT_SORT);
	}

	public void testAttrDef_Formatted_Choice_GPA_Distinction() {

		simpleAttributeResolution("data/attr-format.resolver.2.xml", "data/attr-format.output.2", "FormattedTestUser",
				"urn::test:luminis::sungardsct::com", DO_NOT_SORT);
	}

	public void testAttrDef_Composite_LabeledURI() {

		simpleAttributeResolution("data/attr-composite.resolver.1.xml", "data/attr-composite.output.1",
				"CompositeTestUser", "urn::test:luminis::sungardsct::com", DO_NOT_SORT);
	}

	// Failing Test cases
	// How to test that improperly configured definitions will fail to load. Can we check for the specific error?
	// 
	/**
	 * 1. RegEx - Custom Value Handler (reverses the characters) can be used 2. Mapped - Custom Value Handler (reverses
	 * the characters) can be used 3. Formatted - Custom Value Handler (reverses the characters) can be used 4.
	 * Composite - Custom Value Handler (reverses the characters) can be used - unordered values should fail - Behavior
	 * with unequal number of values
	 */

	/**
	 * Sort the attribute values in the AAAttribute so that equals comparison works as intended
	 */

	private void sort(Map<String, AAAttribute> attrSet) {

		for (Iterator<AAAttribute> iter = attrSet.values().iterator(); iter.hasNext();) {
			ResolverAttribute attr = iter.next();
			if (attr instanceof AAAttribute) {
				ArrayList values = new ArrayList();
				for (Iterator valuesIterator = attr.getValues(); valuesIterator.hasNext();) {
					values.add(valuesIterator.next());
				}
				Object[] sortedValues = values.toArray();
				Arrays.sort(sortedValues);

				((AAAttribute) attr).setValues(sortedValues);
			}
		}
	}

}
