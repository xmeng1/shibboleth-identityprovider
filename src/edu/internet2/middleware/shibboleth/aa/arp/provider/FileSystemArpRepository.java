/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation
 * for Advanced Internet Development, Inc. All rights reserved
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
 * <http://www.ucaid.edu> Internet2 Project. Alternately, this acknowledegement
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
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.aa.arp.provider;

import java.io.File;
import java.io.IOException;
import java.security.Principal;

import org.apache.log4j.Logger;
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
 * Simple <code>ArpRepository</code> implementation that uses a filesystem
 * for storage.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */

public class FileSystemArpRepository extends BaseArpRepository implements ArpRepository {

	private static Logger log = Logger.getLogger(FileSystemArpRepository.class.getName());
	private final String siteArpFileName = "arp.site.xml";

	private String dataStorePath;

	public FileSystemArpRepository(Element config) throws ArpRepositoryException {
		super(config);

		NodeList itemElements = config.getElementsByTagNameNS(IdPConfig.originConfigNamespace, "Path");

		if (itemElements.getLength() > 1) {
			log.warn(
				"Encountered multiple <Path> configuration elements for the File System ARP Repository.  Using first...");
		}
		Node tnode = itemElements.item(0).getFirstChild();
		String path = null;
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			path = tnode.getNodeValue();
		}
		if (path == null || path.equals("")) {
			log.error("ARP repository path not specified.");
			throw new ArpRepositoryException("Cannot initialize FileSystemArpRepository: <ArpRepository> element must contain a <Path> element.");
		}

		try {
			File realPath = new ShibResource(path, this.getClass()).getFile();

			if (!realPath.isDirectory()) {
				log.error(
					"Cannot initialize FileSystemArpRepository: specified path is not a directory: ("
						+ realPath.getPath()
						+ ").");
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
			parser.parse(new InputSource(resource.getInputStream()));
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
