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

/**
 *  Attribute Authority & Release Policy
 *  Attribute Release Policy for a User
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */


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
