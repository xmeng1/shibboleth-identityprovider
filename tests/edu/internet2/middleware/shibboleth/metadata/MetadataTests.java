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

package edu.internet2.middleware.shibboleth.metadata;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Arrays;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.xerces.parsers.DOMParser;
import org.xml.sax.EntityResolver;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import edu.internet2.middleware.shibboleth.metadata.provider.XMLMetadataLoadWrapper;

/**
 * Validation suite for the <code>Metadata</code> interface.
 * 
 * @author Walter Hoehn
 */

public class MetadataTests extends TestCase {

	private DOMParser	parser	= new DOMParser();

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
		try {
			parser.setFeature("http://xml.org/sax/features/validation", true);
			parser.setFeature("http://apache.org/xml/features/validation/schema", true);
			parser.setEntityResolver(new EntityResolver() {

				public InputSource resolveEntity(String publicId, String systemId) throws SAXException {

					if (systemId.endsWith("credentials.xsd")) {
						InputStream stream;
						try {
							stream = new FileInputStream("src/schemas/shibboleth.xsd");
							if (stream != null) {
								return new InputSource(stream);
							}
							throw new SAXException("Could not load entity: Null input stream");
						} catch (FileNotFoundException e) {
							throw new SAXException("Could not load entity: " + e);
						}
					} else if (systemId.endsWith("xmldsig-core-schema.xsd")) {
						InputStream stream;
						try {
							stream = new FileInputStream("src/schemas/xmldsig-core-schema.xsd");
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

	public void testBasicShibbolethXML() {

		try {
			Metadata metadata = new XMLMetadataLoadWrapper(new File("data/sites1.xml").toURL().toString());

			assertNotNull("Unable to find test provider", metadata.lookup("bahsite"));
			assertNotNull("Unable to find test provider", metadata.lookup("rootsite"));

			assertTrue("Group list is incorrect or out of order.", Arrays.equals(new String[]{"urn:mace:inqueue",
					"foofed", "bahfed"}, metadata.lookup("bahsite").getGroups()));

			//This should probably be made more robust at some point
			assertTrue("Incorrect provider role.", metadata.lookup("bahsite").getRoles()[0] instanceof SPProviderRole);
			assertTrue("Incorrect provider role.",
					metadata.lookup("bahsite").getRoles()[0] instanceof AttributeConsumerRole);

			assertEquals("Incorrect parsing of assertion consumer URL.", ((SPProviderRole) metadata.lookup("bahsite")
					.getRoles()[0]).getAssertionConsumerServiceURLs()[0].getLocation(), "http://foo.com/SHIRE");

			assertTrue("Incorrect attribute requester parsing.", metadata.lookup("rootsite").getRoles()[0]
					.getKeyDescriptors().length == 2);

			String[] control = new String[]{
					"C=US, ST=Tennessee, L=Memphis, O=The University of Memphis, OU=Information Systems, CN=test2.memphis.edu",
					"C=US, ST=Tennessee, L=Memphis, O=The University of Memphis, OU=Information Systems, CN=test1.memphis.edu"};
			String[] meta = new String[]{
					metadata.lookup("rootsite").getRoles()[0].getKeyDescriptors()[0].getKeyInfo()[0].itemKeyName(0)
							.getKeyName(),
					metadata.lookup("rootsite").getRoles()[0].getKeyDescriptors()[1].getKeyInfo()[0].itemKeyName(0)
							.getKeyName()};
			Arrays.sort(meta);
			Arrays.sort(control);
			assertTrue("Encountered unexpected key names", Arrays.equals(control, meta));
		} catch (Exception e) {
			fail("Failed to correctly load metadata: " + e);
		}

	}
}