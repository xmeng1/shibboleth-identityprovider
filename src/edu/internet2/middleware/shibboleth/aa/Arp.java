package edu.internet2.middleware.shibboleth.aa;

import java.io.*;
import java.util.*;
import java.security.Principal;
import java.security.acl.*;

public class Arp extends ArpCore implements Serializable{

    // Attributes
    protected String name;
    protected boolean isAdmin;
    private boolean everWritten = false;
    private Date lastRead;
    private boolean hasDefaultShar = false;
    private ArpShar defaultShar;

    // Associations
    protected Vector  shars;

    // Constructors
    public Arp(String name, boolean isAdmin)
	throws NotOwnerException{

	this.name = name;
	this.isAdmin = isAdmin;
	shars  = new Vector();
	makeAcl("arpAcl");
    }

    // Operations
    public boolean isNew(){
	return !everWritten;
    }

    public void setNew(boolean b){
	everWritten = !b;
    }

    public void setLastRead(Date d){
	lastRead = d;
    }

    public Date getLastRead(){
	return lastRead;
    }

    /**
     * Add a new SHAR to the list of SHARs for this ARP.
     * returns false and does not replace if SHAR already exists.
     */
    public boolean addAShar(String name, boolean isDefault)
	throws NotOwnerException,AAPermissionException, AAException{

	if(isDefault &&	hasDefaultShar)
	    throw new AAException("Already has a Default SHAR");

	ArpShar newShar = new ArpShar(name, isDefault);
	if(shars.contains(newShar))
	    return false; // already there
	if(! insertPermitted())
	    throw new AAPermissionException("No INSERT right for "+getCaller());
	shars.add(newShar);
	if(isDefault){
	    hasDefaultShar = true;
	    defaultShar = newShar;
	}
	return true;
    }

    /**
     * Add the given SHAR to the list of SHARs for this ARP.
     * returns false and does not replace if SHAR already exists.
     */
    public boolean addAShar(ArpShar shar)
	throws AAPermissionException, AAException{

	return addAShar(shar, false);
    }

    /**
     * Adds the given shar to the shars for this Arp.
     * if force flag is true and shar already exists
     * then replaces the existing reource otherwise leaves the existing 
     * shar untouched.  
     * returns false if reource already existed.
     * Throws AAPermissionException if caller is not permitted to insert or replace.
     */
    public boolean addAShar(ArpShar shar, boolean force)
	throws AAPermissionException, AAException {
		
	if(shars.contains(shar)){
	    if(force){
		if(! replacePermitted())
		    throw new AAPermissionException("No replace right for "+getCaller());
		shars.remove(shar);
		shars.add(shar);
	    }
	    return false; // already there
	}
	if(! insertPermitted())
	    throw new AAPermissionException("No INSERT right for "+getCaller());
	if(shar.isDefault() &&	hasDefaultShar)
	    throw new AAException("Already has a Default SHAR");

	shars.add(shar);
	if(shar.isDefault()){
	    hasDefaultShar = true;
	    defaultShar = shar;
	}
	return true;
    }



    public boolean removeAShar(String name)
	throws NotOwnerException, AAPermissionException{

	ArpShar newShar = new ArpShar(name, false);
	if(shars.contains(newShar)){
	    if(! removePermitted())
		throw new AAPermissionException("No DELETE rights for "+getCaller());
	    shars.remove(newShar);
	    if(hasDefaultShar && newShar.equals(defaultShar)){
		defaultShar = null;
		hasDefaultShar = false;
	    }
	    return true;
	}
	return false; // not found
    }


    public ArpShar getShar(String name) {
	Enumeration en = shars.elements();
	while(en.hasMoreElements()){
	    ArpShar aShar = (ArpShar)en.nextElement();
	    if(aShar.getName().equals(name))
		return aShar;
	}
	return null;
    }

    public ArpShar[] getShars() {
	int len = shars.size();
	ArpShar[] a = new ArpShar[len];
	for(int i = 0; i < len; i++)
	    a[i] = (ArpShar)shars.get(i);
	return a;
    }

    public ArpShar getDefaultShar(){
	return defaultShar;
    }

    public String getName(){
	return name;
    }

    //public void setAcl(Acl acl){
    //this.acl = acl;
    //}

    //    public String urlToShar(String url) {
    //    }

    public String toString(){
	return name+(isAdmin?"(admin)":"");
    }

    public boolean isAdmin(){
	return isAdmin;
    }

    public boolean equals(Object arp){
	return name.equals(((Arp)arp).getName());
    }

} /* end class Arp */
