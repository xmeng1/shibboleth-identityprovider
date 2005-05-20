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

package edu.internet2.middleware.shibboleth.aa.arp.provider;

import java.io.File;
import java.io.IOException;
import java.security.Principal;

import org.apache.log4j.Logger;
import org.opensaml.SAMLException;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import edu.internet2.middleware.shibboleth.aa.arp.Arp;
import edu.internet2.middleware.shibboleth.aa.arp.ArpRepository;
import edu.internet2.middleware.shibboleth.aa.arp.ArpRepositoryException;
import edu.internet2.middleware.shibboleth.common.ShibResource;
import edu.internet2.middleware.shibboleth.idp.IdPConfig;
import edu.internet2.middleware.shibboleth.xml.Parser;

/**
 * Simple <code>ArpRepository</code> implementation that uses a filesystem for storage.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */

public class FileSystemArpRepository extends BaseArpRepository implements ArpRepository {

	private static Logger log = Logger.getLogger(FileSystemArpRepository.class.getName());
	private final String siteArpFileName = "arp.site.xml";

	private String dataStorePath;

	public FileSystemArpRepository(Element config) throws ArpRepositoryException {

		super(config);

		NodeList itemElements = config.getElementsByTagNameNS(IdPConfig.configNameSpace, "Path");

		if (itemElements.getLength() > 1) {
			log
					.warn("Encountered multiple <Path> configuration elements for the File System ARP Repository.  Using first...");
		}
		Node tnode = itemElements.item(0).getFirstChild();
		String path = null;
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			path = tnode.getNodeValue();
		}
		if (path == null || path.equals("")) {
			log.error("ARP repository path not specified.");
			throw new ArpRepositoryException(
					"Cannot initialize FileSystemArpRepository: <ArpRepository> element must contain a <Path> element.");
		}

		try {
			File realPath = new ShibResource(path, this.getClass()).getFile();

			if (!realPath.isDirectory()) {
				log.error("Cannot initialize FileSystemArpRepository: specified path is not a directory: ("
						+ realPath.getPath() + ").");
				throw new ArpRepositoryException("Cannot initialize FileSystemArpRepository");
			}

			dataStorePath = path;
			if (!dataStorePath.endsWith("/")) {
				dataStorePath += "/";
			}
			log.info("Initializing File System Arp Repository with a root of (" + dataStorePath + ").");
		} catch (Exception e) {
			log.error("Cannot initialize FileSystemArpRepository: error accessing path: (" + path + "): " + e);
			throw new ArpRepositoryException("Cannot initialize FileSystemArpRepository");
		}
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.arp.ArpRepository#remove(Arp)
	 */
	public void remove(Arp arp) throws ArpRepositoryException {

		throw new ArpRepositoryException("Remove not implemented for FileSystemArpRepository.");
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.arp.ArpRepository#update(Arp)
	 */
	public void update(Arp arp) throws ArpRepositoryException {

		throw new ArpRepositoryException("Update not implemented for FileSystemArpRepository.");
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.arp.provider.BaseArpRepository#retrieveSiteArpXml()
	 */
	protected Element retrieveSiteArpXml() throws IOException, SAXException {

		String fileName = dataStorePath + siteArpFileName;
		log.debug("Attempting to load site ARP from: (" + fileName + ").");
		return retrieveArpXml(fileName);

	}

	private Element retrieveArpXml(String fileName) throws SAXException, IOException {

		try {
			ShibResource resource = new ShibResource(fileName, this.getClass());
			if (!resource.getFile().exists()) {
				log.debug("No ARP found.");
				return null;
			}

			Parser.DOMParser parser = new Parser.DOMParser(true);
			try {
				parser.parse(new InputSource(resource.getInputStream()));
			} catch (SAMLException e) {
				throw new SAXException(e);
			}
			return parser.getDocument().getDocumentElement();

		} catch (ShibResource.ResourceNotAvailableException e) {
			log.debug("No ARP found.");
			return null;
		}
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.arp.provider.BaseArpRepository#retrieveUserArpXml(Principal)
	 */
	protected Element retrieveUserArpXml(Principal principal) throws IOException, SAXException {

		String fileName = dataStorePath + "arp.user." + principal.getName() + ".xml";
		log.debug("Attempting to load user (" + principal.getName() + ") ARP from: (" + fileName + ").");
		return retrieveArpXml(fileName);
	}

}
