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

package edu.internet2.middleware.shibboleth.aap;

import java.io.File;
import java.io.FileInputStream;
import java.util.Arrays;
import java.util.Iterator;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLException;
import org.opensaml.XML;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aap.provider.XMLAAP;
import edu.internet2.middleware.shibboleth.metadata.Metadata;
import edu.internet2.middleware.shibboleth.metadata.provider.XMLMetadata;

/**
 * Validation suite for the <code>Metadata</code> interface.
 * 
 * @author Walter Hoehn
 */

public class AAPTests extends TestCase {

	public AAPTests(String name) {
		super(name);
		BasicConfigurator.resetConfiguration();
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	public static void main(String[] args) {
		junit.textui.TestRunner.run(AAPTests.class);
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	protected void setUp() throws Exception {
		super.setUp();
	}

    public void testBasic() {

        try {
            AAP aap = new XMLAAP(new File("src/conf/AAP.xml").toURL().toString());

            assertFalse("anyAttribute was true",aap.anyAttribute());
            
            AttributeRule rule = aap.lookup("affiliation");
            assertNotNull("Unable to find rule", rule);
            assertTrue("Rule wasn't scoped",rule.getScoped());
            assertFalse("Rule was case-sensitive",rule.getCaseSensitive());
            
            SAMLAttribute a1 = new SAMLAttribute(new FileInputStream("data/attribute1.xml"));
            SAMLAttribute a2 = new SAMLAttribute((Element)a1.toDOM().cloneNode(true));
            
            rule = aap.lookup(a1.getName(),a1.getNamespace());
            assertNotNull("Unable to find rule", rule);
            
            rule.apply(a1, null);
            try {
                a1.checkValidity();
                assertTrue("Attribute should have been stripped clean",false);
            }
            catch (SAMLException ex) {
            }
            
            Metadata metadata = new XMLMetadata(new File("src/conf/IQ-sites.xml").toURL().toString());
            rule.apply(a2, metadata.lookup("urn:mace:inqueue:example.edu").getAttributeAuthorityDescriptor(XML.SAML11_PROTOCOL_ENUM));
            a2.checkValidity();
            assertTrue("Value was unexpected","member".equalsIgnoreCase((String)a2.getValues().next()));
            
        } catch (Exception e) {
            fail("Failed to correctly load AAP: " + e);
        }
    }
}