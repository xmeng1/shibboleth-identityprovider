/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
 * provided with the distribution, if any, must include the following acknowledgment: "This product includes software
 * developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu>Internet2 Project.
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

package edu.internet2.middleware.shibboleth.aa.attrresolv;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.opensaml.SAMLException;

import edu.internet2.middleware.shibboleth.aa.AAAttribute;
import edu.internet2.middleware.shibboleth.aa.AAAttributeSet;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttributeSet.ResolverAttributeIterator;
import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.ScopedStringValueHandler;
import edu.internet2.middleware.shibboleth.common.LocalPrincipal;

/**
 * Validation suite for the <code>AttributeResolver</code>.
 * 
 * @author Walter Hoehn(wassa@columbia.edu)
 * @author Vishal Goenka
 */

public class ResolverTests extends TestCase {

	private static Logger log = Logger.getLogger(ResolverTests.class.getName());
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

			AAAttributeSet inputAttributes = new AAAttributeSet(new AAAttribute[]{
					new AAAttribute("urn:mace:dir:attribute-def:eduPersonNickName"),
					new AAAttribute("urn:mace:dir:attribute-def:eduPersonEntitlement")});

			AAAttributeSet outputAttributes = new AAAttributeSet(new AAAttribute[]{new AAAttribute(
					"urn:mace:dir:attribute-def:eduPersonEntitlement",
					new Object[]{"urn:mace:example.edu:exampleEntitlement"})});

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

			AAAttributeSet inputAttributes = new AAAttributeSet(new AAAttribute[]{
					new AAAttribute("urn:mace:dir:attribute-def:eduPersonPrincipalName"), new AAAttribute("foo")});

			AAAttributeSet outputAttributes = new AAAttributeSet(
					new AAAttribute[]{
							// Attribute should have scope appended to connector output
							new AAAttribute("urn:mace:dir:attribute-def:eduPersonPrincipalName",
									new Object[]{"mytestuser@example.edu"}, new ScopedStringValueHandler("example.edu")),
							// Attribute should retain scope from connector output
							new AAAttribute("foo", new Object[]{"bar@example.com"}, new ScopedStringValueHandler(
									"example.edu"))});

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

			AAAttributeSet inputAttributes = new AAAttributeSet(new AAAttribute[]{new AAAttribute("myAffiliation")});

			AAAttributeSet outputAttributes = new AAAttributeSet(new AAAttribute[]{new AAAttribute("myAffiliation",
					new Object[]{"member"})});

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

			AAAttributeSet inputAttributes = new AAAttributeSet(new AAAttribute[]{
					new AAAttribute("urn:mace:dir:attribute-def:eduPersonPrincipalName"),
					new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation"),
					new AAAttribute("urn:mace:dir:attribute-def:eduPersonEntitlement")});

			AAAttributeSet outputAttributes = new AAAttributeSet(new AAAttribute[]{
					new AAAttribute("urn:mace:dir:attribute-def:eduPersonPrincipalName",
							new Object[]{"mytestuser@example.edu"}, new ScopedStringValueHandler("example.edu")),
					new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member"}),
					new AAAttribute("urn:mace:dir:attribute-def:eduPersonEntitlement",
							new Object[]{"urn:mace:example.edu:exampleEntitlement"})});

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

			AAAttributeSet inputAttributes = new AAAttributeSet(new AAAttribute[]{new AAAttribute(
					"urn:mace:dir:attribute-def:eduPersonScopedAffiliation")});

			AAAttributeSet outputAttributes = new AAAttributeSet(new AAAttribute[]{new AAAttribute(
					"urn:mace:dir:attribute-def:eduPersonScopedAffiliation", new Object[]{"member@example.edu"},
					new ScopedStringValueHandler("example.edu"))});

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

			AAAttributeSet inputAttributes = new AAAttributeSet(new AAAttribute[]{new AAAttribute(
					"urn:mace:dir:attribute-def:eduPersonScopedAffiliation")});

			AAAttributeSet outputAttributes = new AAAttributeSet();

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

			AAAttributeSet inputAttributes = new AAAttributeSet(new AAAttribute[]{new AAAttribute(
					"urn:mace:dir:attribute-def:eduPersonScopedAffiliation")});

			AAAttributeSet outputAttributes = new AAAttributeSet();

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

			AAAttributeSet inputAttributes = new AAAttributeSet(new AAAttribute[]{
					new AAAttribute("urn:mace:dir:attribute-def:eduPersonScopedAffiliation"),
					new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation"),
					new AAAttribute("urn:mace:shibboleth:test:eduPersonAffiliation")});

			AAAttributeSet outputAttributes = new AAAttributeSet(new AAAttribute[]{
					new AAAttribute("urn:mace:dir:attribute-def:eduPersonScopedAffiliation",
							new Object[]{"member@example.edu"}, new ScopedStringValueHandler("example.edu")),
					new AAAttribute("urn:mace:dir:attribute-def:eduPersonAffiliation", new Object[]{"member"}),
					new AAAttribute("urn:mace:shibboleth:test:eduPersonAffiliation", new Object[]{"member"})});

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
			ResolverAttributeSet attrsToBeResolved = attrFile.getResolverAttributes(false);
			ar.resolveAttributes(new LocalPrincipal(principal), requester, null, attrsToBeResolved);

			// Read the attribute names and values from the output file
			ResolverAttributeSet expectedAttributes = attrFile.getResolverAttributes(true);

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
	private void sort(ResolverAttributeSet attrSet) {

		for (ResolverAttributeIterator iter = attrSet.resolverAttributeIterator(); iter.hasNext();) {
			ResolverAttribute attr = iter.nextResolverAttribute();
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
