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

package edu.internet2.middleware.shibboleth.aa.arp.provider;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.apache.xerces.parsers.DOMParser;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import edu.internet2.middleware.shibboleth.aa.arp.Arp;
import edu.internet2.middleware.shibboleth.aa.arp.ArpRepository;
import edu.internet2.middleware.shibboleth.aa.arp.ArpRepositoryException;
import edu.internet2.middleware.shibboleth.common.ShibResource;

/**
 * Simple <code>ArpRepository</code> implementation that uses a filesystem for storage.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */

public class FileSystemArpRepository extends BaseArpRepository implements ArpRepository {

	private static Logger log = Logger.getLogger(FileSystemArpRepository.class.getName());
	private final String siteArpFileName = "arp.site.xml";

	private String dataStorePath;

	public FileSystemArpRepository(Properties props) throws ArpRepositoryException {
		super(props);
		if (props.getProperty("edu.internet2.middleware.shibboleth.aa.arp.provider.FileSystemArpRepository.Path", null)
			== null) {
			log.error(
				"Cannot initialize FileSystemArpRepository: attribute (edu.internet2.middleware.shibboleth.aa.arp.provider.FileSystemArpRepository.Path) not specified");
			throw new ArpRepositoryException("Cannot initialize FileSystemArpRepository");
		}

		try {
			File givenPath =
				new ShibResource(
					props.getProperty(
						"edu.internet2.middleware.shibboleth.aa.arp.provider.FileSystemArpRepository.Path"),
					this.getClass())
					.getFile();

			if (!givenPath.isDirectory()) {
				log.error(
					"Cannot initialize FileSystemArpRepository: specified path is not a directory: ("
						+ givenPath.getPath()
						+ ").");
				throw new ArpRepositoryException("Cannot initialize FileSystemArpRepository");
			}

			dataStorePath =
				props.getProperty("edu.internet2.middleware.shibboleth.aa.arp.provider.FileSystemArpRepository.Path");
			if (!dataStorePath.endsWith("/")) {
				dataStorePath += "/";
			}
			log.info("Initializing File System Arp Repository with a root of (" + dataStorePath + ").");
		} catch (IOException e) {
			log.error(
				"Cannot initialize FileSystemArpRepository: error accessing path: ("
					+ props.getProperty(
						"edu.internet2.middleware.shibboleth.aa.arp.provider.FileSystemArpRepository.Path")
					+ ").");
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

	private Element retrieveArpXml(String fileName) throws FileNotFoundException, SAXException, IOException {

		File arpFile = new ShibResource(fileName, this.getClass()).getFile();
		if (!arpFile.exists()) {
			log.debug("No ARP found.");
			return null;
		}

		InputStream inStream = new FileInputStream(fileName);
		DOMParser parser = new DOMParser();
		parser.parse(new InputSource(inStream));
		return parser.getDocument().getDocumentElement();
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.arp.provider.BaseArpRepository#retrieveUserArpXml(Principal)
	 */
	protected Element retrieveUserArpXml(Principal principal) throws IOException, SAXException {
		String fileName =
			dataStorePath
				+ "arp.user."
				+ principal.getName()
				+ ".xml";
		log.debug(
			"Attempting to load user (" + principal.getName() + ") ARP from: (" + fileName + ").");
		return retrieveArpXml(fileName);
	}

}
