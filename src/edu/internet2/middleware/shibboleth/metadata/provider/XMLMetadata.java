/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the
 * above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution, if any, must include the following acknowledgment: "This product includes
 * software developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu>Internet2
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

package edu.internet2.middleware.shibboleth.metadata.provider;

import java.net.URL;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Stack;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.log4j.Logger;
import org.apache.xml.security.Init;
import org.apache.xml.security.keys.KeyInfo;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import edu.internet2.middleware.shibboleth.common.XML;
import edu.internet2.middleware.shibboleth.metadata.AttributeConsumerRole;
import edu.internet2.middleware.shibboleth.metadata.ContactPerson;
import edu.internet2.middleware.shibboleth.metadata.Endpoint;
import edu.internet2.middleware.shibboleth.metadata.KeyDescriptor;
import edu.internet2.middleware.shibboleth.metadata.Metadata;
import edu.internet2.middleware.shibboleth.metadata.MetadataException;
import edu.internet2.middleware.shibboleth.metadata.Provider;
import edu.internet2.middleware.shibboleth.metadata.ProviderRole;
import edu.internet2.middleware.shibboleth.metadata.SPProviderRole;

/**
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public class XMLMetadata implements Metadata {

	private static Logger		log			= Logger.getLogger(XMLMetadata.class.getName());
	public static final String	namespace	= "urn:mace:shibboleth:1.0";
	private Map					providers	= new HashMap();

	public XMLMetadata(Element root) throws MetadataException {
		try {
			new ShibGroup(root, new Stack(), providers);
		} catch (XMLMetadataException e) {
			log.error("Encountered a problem loadign federation metadata: " + e);
			throw new MetadataException("Unable to load federation metadata.");
		}
	}

	public Provider lookup(String providerId) {
		if (providers.containsKey(providerId)) {
			return (Provider) providers.get(providerId);
		}
		return null;
	}

	private class ShibGroup {

		private String	id;

		ShibGroup(Element root, Stack parents, Map providers) throws XMLMetadataException {
			if (!root.getNodeName().equals("SiteGroup")) {
				throw new XMLMetadataException("Excpected \"SiteGroup\", found \"" + root.getNodeName() + "\".");
			}

			id = root.getAttribute("Name");
			if (id == null || id.equals("")) {
				throw new XMLMetadataException("A name must be specified for the site group.");
			}

			parents.push(id);
			NodeList nodes = root.getChildNodes();
			for (int i = 0; nodes.getLength() > i; i++) {
				if (nodes.item(i).getNodeType() == Node.ELEMENT_NODE) {

					if (nodes.item(i).getNodeName().equals("SiteGroup")) {
						new ShibGroup((Element) nodes.item(i), parents, providers);

					} else if (nodes.item(i).getNodeName().equals("DestinationSite")) {

						Provider provider = new ShibTargetXMLProvider((Element) nodes.item(i), (String[]) parents
								.toArray(new String[0]));
						providers.put(provider.getId(), provider);

					} else if (nodes.item(i).getNodeName().equals("OriginSite")) {
						log.debug("Ignoring OriginSite.");
					}
				}
			}
			parents.pop();
		}
	}

	class ShibTargetXMLProvider implements Provider, ProviderRole, SPProviderRole, AttributeConsumerRole {

		private String		id;
		private HashSet		contacts;
		private String[]	groups;
		private HashSet		assertionConsumers	= new HashSet();
		private HashSet		keyDescriptors		= new HashSet();

		ShibTargetXMLProvider(Element element, String[] groups) throws XMLMetadataException {
			if (!element.getNodeName().equals("DestinationSite")) {
				log.error("This provider implementation can only marshall Shibboleth target metadata.");
				throw new XMLMetadataException("Unable to load provider.");
			}

			this.groups = groups;

			id = element.getAttribute("Name");
			if (id == null || id.equals("")) {
				log.error("No name set for provider.");
				throw new XMLMetadataException("Unable to load provider.");
			}

			NodeList contactNodes = element.getElementsByTagNameNS(namespace, "Contact");
			if (contactNodes.getLength() > 0) {
				contacts = new HashSet();
			}
			for (int i = 0; contactNodes.getLength() > i; i++) {
				try {
					contacts.add(new XMLContactPerson((Element) contactNodes.item(i)));
				} catch (XMLMetadataException e) {
					log.error("Error loading parsing contact person for provider (" + id + "): " + e.getMessage());
				}
			}

			NodeList consumerNodes = element.getElementsByTagNameNS(namespace, "AssertionConsumerServiceURL");
			for (int i = 0; consumerNodes.getLength() > i; i++) {
				String location = ((Element) consumerNodes.item(i)).getAttribute("Location");
				if (location == null || location.equals("")) {
					log.error("Destination site (" + id + ") contained a malformed Assertion Consumer Service URL.");
					continue;
				}
				assertionConsumers.add(new ShibEndpoint(location));
			}
			if (assertionConsumers.size() == 0) {
				log.error("No assertion consumer URLs specified for this provider.");
				throw new XMLMetadataException("Unable to load provider.");
			}

			NodeList requesterNodes = element.getElementsByTagNameNS(namespace, "AttributeRequester");
			for (int i = 0; requesterNodes.getLength() > i; i++) {
				String name = ((Element) requesterNodes.item(i)).getAttribute("Name");
				if (name == null || name.equals("")) {
					log.error("Destination site (" + id + ") contained a malformed Attribute Requester name.");
					continue;
				}

				DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
				try {
					if (!Init.isInitialized()) {
						org.apache.xml.security.Init.init();
					}
					KeyInfo keyInfo = new KeyInfo(docFactory.newDocumentBuilder().newDocument());
					keyInfo.addKeyName(name);
					keyDescriptors.add(new TargetKeyDescriptor(keyInfo));

				} catch (ParserConfigurationException e) {
					log.error("Unable to create xml document needed for KeyInfo.");
				}
			}
			if (keyDescriptors.size() == 0) {
				log.error("No valid attribute requesters specified for this provider.");
				throw new XMLMetadataException("Unable to load provider.");
			}

		}

		public String getId() {
			return id;
		}

		public String[] getGroups() {
			return groups;
		}

		public ContactPerson[] getContacts() {
			if (contacts != null) {
				return (ContactPerson[]) contacts.toArray(new ContactPerson[0]);
			}
			return new ContactPerson[0];
		}

		public ProviderRole[] getRoles() {
			return new ProviderRole[]{this};
		}

		public Provider getProvider() {
			return this;
		}

		public String[] getProtocolSupport() {
			return new String[]{XML.SHIB_NS};
		}

		public boolean hasSupport(String version) {
			if (version.equals(XML.SHIB_NS)) {
				return true;
			} else {
				return false;
			}
		}

		public Endpoint[] getDefaultEndpoints() {
			return new Endpoint[0];
		}

		public URL getErrorURL() {
			return null;
		}

		public boolean getAuthnRequestsSigned() {
			return true;
		}

		public Endpoint[] getAssertionConsumerServiceURLs() {
			return (Endpoint[]) assertionConsumers.toArray(new Endpoint[0]);
		}

		public KeyDescriptor[] getKeyDescriptors() {
			return (KeyDescriptor[]) keyDescriptors.toArray(new KeyDescriptor[0]);
		}

		class ShibEndpoint implements Endpoint {

			private String	binding;
			private String	location;

			ShibEndpoint(String location) {
				this.location = location;
			}

			public String getBinding() {
				return XML.SHIB_NS;
			}

			public String getVersion() {
				return null;
			}

			public String getLocation() {
				return location;
			}

			public String getResponseLocation() {
				return null;
			}
		}

		class TargetKeyDescriptor implements KeyDescriptor {

			private KeyInfo	keyInfo;

			TargetKeyDescriptor(KeyInfo keyInfo) {
				this.keyInfo = keyInfo;
			}

			public int getUse() {
				return ENCRYPTION;
			}

			public String getEncryptionMethod() {
				return null;
			}

			public int getKeySize() {
				return 0;
			}

			public KeyInfo[] getKeyInfo() {
				return new KeyInfo[]{keyInfo};
			}
		}

	}

	class XMLContactPerson implements ContactPerson {

		private int		type;
		private String	name;
		private String	email;

		public XMLContactPerson(Element element) throws XMLMetadataException {
			String rawType = element.getAttribute("Type");
			if (rawType.equalsIgnoreCase("TECHNICAL")) {
				type = ContactPerson.TECHNICAL;
			} else if (rawType.equalsIgnoreCase("SUPPORT")) {
				type = ContactPerson.SUPPORT;
			} else if (rawType.equalsIgnoreCase("ADMINISTRATIVE")) {
				type = ContactPerson.ADMINISTRATIVE;
			} else if (rawType.equalsIgnoreCase("BILLING")) {
				type = ContactPerson.BILLING;
			} else if (rawType.equalsIgnoreCase("OTHER")) {
				type = ContactPerson.OTHER;
			} else {
				throw new XMLMetadataException("Unknown contact type.");
			}
			name = element.getAttribute("Name");
			if (name == null || name.equals("")) {
				throw new XMLMetadataException("No contact name.");
			}
			email = element.getAttribute("Email");
		}

		public int getType() {
			return type;
		}

		public String getName() {
			return name;
		}

		public String[] getEmails() {
			if (email != null & !email.equals("")) {
				return new String[]{email};
			}
			return new String[0];
		}

		public String[] getTelephones() {
			return new String[0];
		}
	}

	class XMLMetadataException extends Exception {

		XMLMetadataException(String message) {
			super(message);
		}
	}
}
