/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the
 * above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution, if any, must include the following acknowledgment: "This product includes
 * software developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu> Internet2
 * Project. Alternately, this acknowledegement may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear. Neither the name of Shibboleth nor the names of its contributors, nor Internet2,
 * nor the University Corporation for Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote
 * products derived from this software without specific prior written permission. For written permission, please
 * contact shibboleth@shibboleth.org Products derived from this software may not be called Shibboleth, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor may Shibboleth appear in their name,
 * without prior written permission of the University Corporation for Advanced Internet Development. THIS SOFTWARE IS
 * PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND
 * NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS
 * WITH LICENSEE. IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY CORPORATION FOR ADVANCED
 * INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.aa;

import javax.security.auth.x500.X500Principal;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import edu.internet2.middleware.shibboleth.common.ShibBrowserProfile;

/**
 * Validation suite for hack to pull hostnames out of a subject DN.
 * 
 * @author Walter Hoehn(wassa@columbia.edu)
 */
public class DNHostNameExtractionTests extends TestCase {

	//Basic
	String	dn1	= "CN=wayf.internet2.edu,OU=TSG,O=University Corporation for Advanced Internet Development,L=Ann Arbor,ST=Michigan,C=US";

	//lowercase CN
	String	dn2	= "cn=wayf.internet2.edu,OU=TSG,O=University Corporation for Advanced Internet Development,L=Ann Arbor,ST=Michigan,C=US";

	//Multiple CNs
	String	dn4	= "CN=wayf.internet2.edu,OU=TSG, CN=foo, O=University Corporation for Advanced Internet Development,L=Ann Arbor,ST=Michigan,C=US";

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
			assertEquals("Round-trip handle validation failed on DN.", ShibBrowserProfile
					.getHostNameFromDN(new X500Principal(dn1)), "wayf.internet2.edu");

		} catch (Exception e) {
			fail("Error in test specification: " + e.getMessage());
		}
	}

	public void testExtractionWithLowerCaseAttrName() {

		try {
			assertEquals("Round-trip handle validation failed on DN.", ShibBrowserProfile
					.getHostNameFromDN(new X500Principal(dn2)), "wayf.internet2.edu");

		} catch (Exception e) {
			fail("Error in test specification: " + e.getMessage());
		}
	}

	public void testExtractionWithMultipleCNs() {

		try {
			assertEquals("Round-trip handle validation failed on DN.", ShibBrowserProfile
					.getHostNameFromDN(new X500Principal(dn4)), "wayf.internet2.edu");

		} catch (Exception e) {
			fail("Error in test specification: " + e.getMessage());
		}
	}

}
