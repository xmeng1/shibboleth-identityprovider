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

package edu.internet2.middleware.shibboleth.aa;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.security.acl.NotOwnerException;
import java.util.Date;
import java.util.Properties;

import org.apache.log4j.Logger;

/**
 *  Attribute Authority & Release Policy
 *  File implementation of a repository for ARPs
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */

public class FileArpRepository implements ArpRepository {

	private String dataStorePath;
	private static Logger log = Logger.getLogger(FileArpRepository.class.getName());
	public FileArpRepository(Properties props) throws ArpRepositoryException {
		
		if (props.getProperty("edu.internet2.middleware.shibboleth.aa.FileArpRepository.Path", null) == null) {
			log.error("Cannot initialize FileArpRepository: attribute (edu.internet2.middleware.shibboleth.aa.FileArpRepository.Path) not specified");
			throw new ArpRepositoryException("Cannot initialize FileArpRepository");
		}
		
		File givenPath = new File(props.getProperty("edu.internet2.middleware.shibboleth.aa.FileArpRepository.Path"));
		if (!givenPath.isDirectory()) {
			log.error("Cannot initialize FileArpRepository: specified path is not a directory.");
			throw new ArpRepositoryException("Cannot initialize FileArpRepository");		
		}
		
		log.info("Initializing File Arp Repository with a root of (" + givenPath.getAbsolutePath() + ").");
		dataStorePath = props.getProperty("edu.internet2.middleware.shibboleth.aa.FileArpRepository.Path");
	}

	public Arp lookupArp(String arpName, boolean isAdmin) throws ArpRepositoryException {
		try {

			String fileName = dataStorePath + System.getProperty("file.separator") + arpName;
			log.info("Searching for ARP " + arpName);
			log.debug("Looking at : " + fileName);
			
			File arpFile = new File(fileName);
			if (!arpFile.exists()) {
				return null;	
			}

			FileInputStream f = new FileInputStream(fileName);
			ObjectInput s = new ObjectInputStream(f);
			Arp arp = (Arp) s.readObject();
			if (!arpName.equals(arp.getName())) {
				log.warn("Unexpected ARP name: expected - (" + arpName + ") actual - (" + arp.getName() + ")");
			}
			arp.setNew(false);
			arp.setLastRead(new Date());
			log.info("AA: Found and using ARP " + arpName);
			return arp;
		} catch (FileNotFoundException fnfe) {
			log.error("Unable to read ARP storage: " + fnfe.getMessage());
			throw new ArpRepositoryException("Unable to read ARP storage.");			
		} catch (IOException ioe) {
			log.error("Unable to unmarshall ARP from file: " + ioe.getMessage());
			throw new ArpRepositoryException("Unable to unmarshall ARP.");	
		} catch (ClassNotFoundException cnfe) {
			log.error("Serious Problem! Unable to unmarhsall ARP because (Arp) class not found: " + cnfe.getMessage());
			throw new ArpRepositoryException("Unable to unmarshall ARP.");	
		}
	}

	public void update(Arp arp) throws ArpRepositoryException {

		try {
			String fileName = dataStorePath + System.getProperty("file.separator") + arp.getName();
			FileOutputStream f = new FileOutputStream(fileName);
			ObjectOutput s = new ObjectOutputStream(f);
			s.writeObject(arp);
			s.flush();
			arp.setNew(false);
		} catch (FileNotFoundException e) {
			log.error("Unable to write ARP to file:" + e.getMessage());
			throw new ArpRepositoryException("Unable to update ARP.");
		} catch (IOException ioe) {
			log.error("Error serializing ARP:" + ioe.getMessage());
			throw new ArpRepositoryException("Unable to update ARP.");
		}
	}

	public void remove(Arp arp) throws ArpRepositoryException {
		try {
		String fileName = dataStorePath + System.getProperty("file.separator") + arp.getName();
		File f = new File(fileName);
		f.delete();
		} catch (SecurityException e) {
			log.error("Cannot write ARP with current Security Manager configuration" + e.getMessage());
			throw new ArpRepositoryException("Unable to remove ARP.");
		}
	}

	public String toString() {
		return "FileArpRepository:dir=" + dataStorePath;
	}
}
