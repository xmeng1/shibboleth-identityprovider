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

public class ArpFileFactory implements ArpFactory {

	static String dataStore;
	private static Logger log = Logger.getLogger(ArpFileFactory.class.getName());
	public ArpFileFactory(Properties props) {
		String pathData = props.getProperty("arpFactoryData");
		if (pathData == null) {
			String realPath = props.getProperty("arpFactoryRealPath");
			realPath += "arps";
			log.debug("shib dir = " + realPath);
			pathData = realPath;
		}
		dataStore = pathData;
	}

	/**
	 * returns an Arp instance. It tries to retrieve the Arp from file system
	 * If not found then creates a new emplty Arp.  
	 * Arp can be check by its isNew() to see how it was generated
	 */

	public Arp getInstance(String arpName, boolean isAdmin) throws AAException {
		try {

			String fileName = dataStore + System.getProperty("file.separator") + arpName;
			log.info("AA: Looking for ARP " + fileName);

			FileInputStream f = new FileInputStream(fileName);
			ObjectInput s = new ObjectInputStream(f);
			Arp arp = (Arp) s.readObject();
			if (!arpName.equals(arp.getName()))
				throw new AAException("Wrong ARP name.  ARP maybe renamed in datastore. ");
			arp.setNew(false);
			arp.setLastRead(new Date());
			log.info("AA: Found and using ARP " + arpName);
			return arp;

		} catch (FileNotFoundException e) {
			// check the IO error to make sure "file not found"
			log.info("AA: Got File Not Found for " + arpName + " in " + dataStore);
			try {
				Arp arp = new Arp(arpName, isAdmin);
				arp.setNew(true);
				arp.setLastRead(new Date());
				return arp;
			} catch (NotOwnerException noe) {
				throw new AAException("Cannot create an ARP. Not owner.");
			}

		} catch (IOException fe) {
			throw new AAException("Reading ARP failed: " + fe);
		} catch (ClassNotFoundException ce) {
			throw new AAException("ARP retrival failed: " + ce);
		} catch (Exception oe) {
			throw new AAException(oe.toString());
		}
	}

	public void write(Arp arp) throws AAException {
		// XXX do we need to check any permissions?
		try {
			String fileName = dataStore + System.getProperty("file.separator") + arp.getName();
			FileOutputStream f = new FileOutputStream(fileName);
			ObjectOutput s = new ObjectOutputStream(f);
			arp.setNew(false);
			s.writeObject(arp);
			s.flush();
		} catch (IOException e) {
			throw new AAException("IO Problem:" + e);
		}
	}

	/**
	 * Reread the arp from file system if the copy on disk
	 * is newer than the copy in memory.
	 */

	public Arp reread(Arp arp) throws AAException {
		String fileName = dataStore + System.getProperty("file.separator") + arp.getName();
		File file = new File(fileName);
		if (file == null)
			throw new AAException("Arp not found on disk while trying to re-read. :" + arp);
		Date timeStamp = new Date(file.lastModified());
		log.info(
			"AA: Check ARP's freshness: in memory ("
				+ arp.getLastRead()
				+ ") vs on disk ("
				+ timeStamp
				+ ")");
		if (timeStamp.after(arp.getLastRead())) {
			log.info("AA: ARP has been modified on disk. Re-read " + arp.getName());
			return getInstance(arp.getName(), arp.isAdmin());
		}
		return arp; // return the old one.
	}

	public void remove(Arp arp) throws AAException {
		try {
			String fileName = dataStore + System.getProperty("file.separator") + arp.getName();
			File f = new File(fileName);
			f.delete();
		} catch (Exception e) {
			throw new AAException("IO Problem:" + e);
		}
	}

	public String toString() {
		return "ArpFileFactory:dir=" + dataStore;
	}
}
