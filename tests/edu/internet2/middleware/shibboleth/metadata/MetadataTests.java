/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
 * provided with the distribution, if any, must include the following acknowledgment: "This product includes software
 * developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu> Internet2 Project.
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

package edu.internet2.middleware.shibboleth.metadata;

import java.io.File;
import java.io.FileInputStream;
import java.util.Arrays;
import java.util.Iterator;

import javax.xml.parsers.DocumentBuilderFactory;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.opensaml.XML;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import edu.internet2.middleware.shibboleth.common.Constants;
import edu.internet2.middleware.shibboleth.idp.IdPConfig;
import edu.internet2.middleware.shibboleth.metadata.provider.XMLMetadata;
import edu.internet2.middleware.shibboleth.xml.Parser;

/**
 * Validation suite for the <code>Metadata</code> interface.
 * 
 * @author Walter Hoehn
 */

public class MetadataTests extends TestCase {

	private Parser.DOMParser parser = new Parser.DOMParser(true);

	public MetadataTests(String name) {

		super(name);
		BasicConfigurator.resetConfiguration();
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	public static void main(String[] args) {

		junit.textui.TestRunner.run(MetadataTests.class);
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	protected void setUp() throws Exception {

		super.setUp();

	}

	public void testBasicShibbolethXML() {

		try {
			Metadata metadata = new XMLMetadata(new File("data/sites1.xml").toURL().toString());

			assertNotNull("Unable to find test provider", metadata.lookup("bahsite"));
			assertNotNull("Unable to find test provider", metadata.lookup("rootsite"));

			// This should probably be made more robust at some point
			assertNotNull("Incorrect provider role.", metadata.lookup("bahsite").getSPSSODescriptor(
					XML.SAML11_PROTOCOL_ENUM));

			assertEquals("Incorrect parsing of assertion consumer URL.", ((Endpoint) metadata.lookup("bahsite")
					.getSPSSODescriptor(XML.SAML11_PROTOCOL_ENUM).getAssertionConsumerServiceManager().getEndpoints()
					.next()).getLocation(), "http://foo.com/SHIRE");

			Iterator keys = metadata.lookup("rootsite").getSPSSODescriptor(XML.SAML11_PROTOCOL_ENUM)
					.getKeyDescriptors();
			KeyDescriptor key1 = (KeyDescriptor) keys.next();
			KeyDescriptor key2 = (KeyDescriptor) keys.next();
			assertTrue("Incorrect attribute requester key parsing.", key1 != null && key2 != null);

			String[] control = new String[]{
					"C=US, ST=Tennessee, L=Memphis, O=The University of Memphis, OU=Information Systems, CN=test2.memphis.edu",
					"C=US, ST=Tennessee, L=Memphis, O=The University of Memphis, OU=Information Systems, CN=test1.memphis.edu"};
			String[] meta = new String[]{key1.getKeyInfo().itemKeyName(0).getKeyName(),
					key2.getKeyInfo().itemKeyName(0).getKeyName()};
			Arrays.sort(meta);
			Arrays.sort(control);
			assertTrue("Encountered unexpected key names", Arrays.equals(control, meta));
		} catch (Exception e) {
			fail("Failed to correctly load metadata: " + e);
		}
	}

	public void testBasicSAMLXML() {

		try {
			Metadata metadata = new XMLMetadata(new File("src/conf/IQ-sites.xml").toURL().toString());

			EntityDescriptor entity = metadata.lookup("urn:mace:inqueue:example.edu");

			assertNotNull("Unable to find test provider", entity);
			assertEquals("Descriptor group is wrong.", entity.getEntitiesDescriptor().getName(), "urn:mace:inqueue");

			IDPSSODescriptor idp = entity.getIDPSSODescriptor(edu.internet2.middleware.shibboleth.common.XML.SHIB_NS);
			AttributeAuthorityDescriptor aa = entity.getAttributeAuthorityDescriptor(XML.SAML11_PROTOCOL_ENUM);
			SPSSODescriptor sp = entity.getSPSSODescriptor(XML.SAML11_PROTOCOL_ENUM);

			assertNotNull("Missing IdP provider role.", idp);
			assertNotNull("Missing AA provider role.", aa);
			assertNotNull("Missing SP provider role.", sp);

			assertEquals("Incorrect assertion consumer service location.", ((Endpoint) sp
					.getAssertionConsumerServiceManager().getEndpoints().next()).getLocation(),
					"https://wayf.internet2.edu/Shibboleth.shire");

			Iterator keys = sp.getKeyDescriptors();
			KeyDescriptor key = (KeyDescriptor) keys.next();
			assertNotNull("Incorrect attribute requester key parsing.", key);

			String[] control = new String[]{"wayf.internet2.edu"};
			String[] meta = new String[]{key.getKeyInfo().itemKeyName(0).getKeyName()};
			Arrays.sort(meta);
			Arrays.sort(control);
			assertTrue("Encountered unexpected key names", Arrays.equals(control, meta));
		} catch (Exception e) {
			fail("Failed to correctly load metadata: " + e);
		}
	}

	public void testInlineSAMLXML() {

		try {

			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			docFactory.setNamespaceAware(true);
			Document placeHolder = docFactory.newDocumentBuilder().newDocument();

			Element providerNode = placeHolder.createElementNS(IdPConfig.configNameSpace, "MetadataProvider");

			Document xmlConfig = parser.parse(new InputSource(new FileInputStream("src/conf/IQ-sites.xml")));
			Node metadataNode = placeHolder.importNode(xmlConfig.getDocumentElement(), true);
			providerNode.appendChild(metadataNode);

			Metadata metadata = new XMLMetadata(providerNode);

			EntityDescriptor entity = metadata.lookup("urn:mace:inqueue:example.edu");

			assertNotNull("Unable to find test provider", entity);
			assertEquals("Descriptor group is wrong.", entity.getEntitiesDescriptor().getName(), "urn:mace:inqueue");

			IDPSSODescriptor idp = entity.getIDPSSODescriptor(edu.internet2.middleware.shibboleth.common.XML.SHIB_NS);
			AttributeAuthorityDescriptor aa = entity.getAttributeAuthorityDescriptor(XML.SAML11_PROTOCOL_ENUM);
			SPSSODescriptor sp = entity.getSPSSODescriptor(XML.SAML11_PROTOCOL_ENUM);

			assertNotNull("Missing IdP provider role.", idp);
			assertNotNull("Missing AA provider role.", aa);
			assertNotNull("Missing SP provider role.", sp);

			assertEquals("Incorrect assertion consumer service location.", ((Endpoint) sp
					.getAssertionConsumerServiceManager().getEndpoints().next()).getLocation(),
					"https://wayf.internet2.edu/Shibboleth.shire");

			Iterator keys = sp.getKeyDescriptors();
			KeyDescriptor key = (KeyDescriptor) keys.next();
			assertNotNull("Incorrect attribute requester key parsing.", key);

			String[] control = new String[]{"wayf.internet2.edu"};
			String[] meta = new String[]{key.getKeyInfo().itemKeyName(0).getKeyName()};
			Arrays.sort(meta);
			Arrays.sort(control);
			assertTrue("Encountered unexpected key names", Arrays.equals(control, meta));
		} catch (Exception e) {
			fail("Failed to correctly load metadata: " + e);
		}
	}

    public void testExtensionSAMLXML() {

        try {
            Metadata metadata = new XMLMetadata(new File("data/metadata10.xml").toURL().toString());

            EntityDescriptor entity = metadata.lookup("urn-x:testSP1");
            assertNotNull("Unable to find test provider", entity);

            AttributeRequesterDescriptor ar = entity.getAttributeRequesterDescriptor(XML.SAML11_PROTOCOL_ENUM);
            assertNotNull("Missing AR provider role.", ar);
            
            Iterator formats = ar.getNameIDFormats();
            assertTrue("Encountered unexpected NameIDFormat", formats.hasNext() && Constants.SHIB_NAMEID_FORMAT_URI.equals(formats.next()));
        } catch (Exception e) {
            fail("Failed to correctly load metadata: " + e);
        }
    }
}
