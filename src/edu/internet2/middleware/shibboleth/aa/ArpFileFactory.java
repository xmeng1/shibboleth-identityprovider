package edu.internet2.middleware.shibboleth.aa;

import java.io.*;
import java.util.Date;
import java.security.acl.*;
import java.security.Principal;
import org.apache.log4j.Logger;

public class ArpFileFactory implements ArpFactory{

    static String dataStore;
    private static Logger log = Logger.getLogger(ArpFileFactory.class.getName());    
    public ArpFileFactory(String pathData){
	dataStore = pathData;
    }

    /**
     * returns an Arp instance. It tries to retrieve the Arp from file system
     * If not found then creates a new emplty Arp.  
     * Arp can be check by its isNew() to see how it was generated
     */

    public Arp getInstance(String arpName, boolean isAdmin)
    throws AAException{
	try{

	    String fileName = dataStore+System.getProperty("file.separator")+arpName;
	    log.info("AA: Looking for ARP "+fileName);

	    FileInputStream f = new FileInputStream(fileName);
	    ObjectInput s = new ObjectInputStream(f);
	    Arp arp = (Arp)s.readObject();
	    if(!arpName.equals(arp.getName()))
	       throw new AAException("Wrong ARP name.  ARP maybe renamed in datastore. ");
	    arp.setNew(false);
	    arp.setLastRead(new Date());
	    log.info("AA: Found and using ARP "+arpName);
	    return arp;
	    
	}catch(FileNotFoundException e){
	    // check the IO error to make sure "file not found"
	    log.info("AA: Got File Not Found for "+arpName+" in "+dataStore);
	    try{
		Arp arp = new Arp(arpName, isAdmin);
		arp.setNew(true);
		arp.setLastRead(new Date());
		return arp;
	    }catch(NotOwnerException noe){
		throw new AAException("Cannot create an ARP. Not owner.");
	    }

	}catch(IOException fe){
	    throw new AAException("Reading ARP failed: "+fe);
	}catch(ClassNotFoundException ce){
	    throw new AAException("ARP retrival failed: "+ce);
	}catch(Exception oe){
	    throw new AAException(oe.toString());
	}
    }

    public void write(Arp arp) throws AAException{
	// XXX do we need to check any permissions?
	try{
	    String fileName = dataStore+System.getProperty("file.separator")+arp.getName();
	    FileOutputStream f = new FileOutputStream(fileName);
	    ObjectOutput s = new ObjectOutputStream(f);
	    arp.setNew(false);
	    s.writeObject(arp);
	    s.flush();	    
	}catch(IOException e){
	    throw new AAException("IO Problem:"+e);
	}
    }

    /**
     * Reread the arp from file system if the copy on disk
     * is newer than the copy in memory.
     */

    public Arp reread(Arp arp) throws AAException{
	String fileName = dataStore+System.getProperty("file.separator")+arp.getName();
	File file = new File(fileName);
	if(file == null)
	    throw new AAException("Arp not found on disk while trying to re-read. :"+arp);
	Date timeStamp = new Date(file.lastModified());
	log.info("AA: Check ARP's freshness: in memory ("+arp.getLastRead()+") vs on disk ("+timeStamp+")");
	if(timeStamp.after(arp.getLastRead())){
	    log.info("AA: ARP has been modified on disk. Re-read "+arp.getName());
	    return getInstance(arp.getName(), arp.isAdmin());
	}
	return arp;  // return the old one.
    }

    public void remove(Arp arp) throws AAException{
	try{
	    String fileName = dataStore+System.getProperty("file.separator")+arp.getName();
	    File f = new File(fileName);
	    f.delete();
	}catch(Exception e){
	    throw new AAException("IO Problem:"+e);
	}
    }

    public String toString(){
	return "ArpFileFactory:dir="+dataStore;
    }
}

