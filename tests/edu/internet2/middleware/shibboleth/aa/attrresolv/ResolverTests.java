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

package edu.internet2.middleware.shibboleth.aa.attrresolv;

import java.io.File;
import java.net.MalformedURLException;
import java.util.Properties;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.opensaml.SAMLException;

import sun.security.acl.PrincipalImpl;
import edu.internet2.middleware.shibboleth.aa.AAAttribute;
import edu.internet2.middleware.shibboleth.aa.AAAttributeSet;
import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.ScopedStringValueHandler;

/**
 * Validation suite for the <code>AttributeResolver</code>.
 * 
 * @ author Walter Hoehn(wassa@columbia.edu)
 */

public class ResolverTests extends TestCase {

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
			Properties props = new Properties();
			File file = new File("data/resolver1.xml");
			props.setProperty(
				"edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver.ResolverConfig",
				file.toURL().toString());

			AttributeResolver ar = new AttributeResolver(props);

			AAAttributeSet inputAttributes =
				new AAAttributeSet(
					new AAAttribute[] {
						new AAAttribute("urn:mace:eduPerson:1.0:eduPersonNickName"),
						new AAAttribute("urn:mace:eduPerson:1.0:eduPersonEntitlement")});

			AAAttributeSet outputAttributes =
				new AAAttributeSet(
					new AAAttribute[] {
						 new AAAttribute(
							"urn:mace:eduPerson:1.0:eduPersonEntitlement",
							new Object[] { "urn:mace:example.edu:exampleEntitlement" })
						});

			ar.resolveAttributes(new PrincipalImpl("mytestuser"), "shar.example.edu", inputAttributes);

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
			Properties props = new Properties();
			File file = new File("data/resolver2.xml");
			props.setProperty(
				"edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver.ResolverConfig",
				file.toURL().toString());

			AttributeResolver ar = new AttributeResolver(props);

			AAAttributeSet inputAttributes =
				new AAAttributeSet(
					new AAAttribute[] {
						new AAAttribute("urn:mace:eduPerson:1.0:eduPersonPrincipalName"),
						new AAAttribute("foo")});

			AAAttributeSet outputAttributes = new AAAttributeSet(new AAAttribute[] {
				//Attribute should have scope appended to connector output
				new AAAttribute(
					"urn:mace:eduPerson:1.0:eduPersonPrincipalName",
					new Object[] { "mytestuser@example.edu" },
					new ScopedStringValueHandler("example.edu")),
				//Attribute should retain scope from connector output
				new AAAttribute(
					"foo",
					new Object[] { "bar@example.com" },
					new ScopedStringValueHandler("example.edu"))
				});

			ar.resolveAttributes(new PrincipalImpl("mytestuser"), "shar.example.edu", inputAttributes);
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
			Properties props = new Properties();
			File file = new File("data/resolver3.xml");
			props.setProperty(
				"edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver.ResolverConfig",
				file.toURL().toString());

			AttributeResolver ar = new AttributeResolver(props);
			fail("Attribute Resolver loaded even when no PlugIns were configured.");
		} catch (AttributeResolverException e) {
			//This exception should be thrown, ignoring
		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		}
	}
		
	public void testExceptionForNoValidPlugIns() {

		try {
			Properties props = new Properties();
			File file = new File("data/resolver4.xml");
			props.setProperty(
				"edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver.ResolverConfig",
				file.toURL().toString());

			AttributeResolver ar = new AttributeResolver(props);
			fail("Attribute Resolver loaded even when no PlugIns were successfully registered.");
		} catch (AttributeResolverException e) {
			//This exception should be thrown, ignoring
		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		}
	}
		
	public void testFailToLoadCircularDependencies() {

		try {
			Properties props = new Properties();
			File file = new File("data/resolver5.xml");
			props.setProperty(
				"edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver.ResolverConfig",
				file.toURL().toString());

			AttributeResolver ar = new AttributeResolver(props);
			fail("Attribute Resolver loaded even when no only PlugIns with circular dependencies were configured.");
		} catch (AttributeResolverException e) {
			//This exception should be thrown, ignoring
		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		}
	}
	
	public void testFailToLoadCircularDependenciesDeeper() {

		try {
			Properties props = new Properties();
			File file = new File("data/resolver6.xml");
			props.setProperty(
				"edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver.ResolverConfig",
				file.toURL().toString());

			AttributeResolver ar = new AttributeResolver(props);
			fail("Attribute Resolver loaded even when no only PlugIns with circular dependencies were configured.");
		} catch (AttributeResolverException e) {
			//This exception should be thrown, ignoring
		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		}
	}

	public void testSourceNameMapping() {

		try {
			Properties props = new Properties();
			File file = new File("data/resolver7.xml");
			props.setProperty(
				"edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver.ResolverConfig",
				file.toURL().toString());

			AttributeResolver ar = new AttributeResolver(props);

			AAAttributeSet inputAttributes = new AAAttributeSet(new AAAttribute[] { new AAAttribute("myAffiliation")});

			AAAttributeSet outputAttributes =
				new AAAttributeSet(new AAAttribute[] { new AAAttribute("myAffiliation", new Object[] { "member" })
			});

			ar.resolveAttributes(new PrincipalImpl("mytestuser"), "shar.example.edu", inputAttributes);
			assertEquals("Attribute Resolver returned unexpected attribute set.", inputAttributes, outputAttributes);

		} catch (AttributeResolverException e) {
			fail("Couldn't load attribute resolver: " + e.getMessage());
		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (SAMLException e) {
			fail("Error creating SAML Attribute: " + e.getMessage());
		}
	}

}
