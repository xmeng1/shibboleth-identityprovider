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
 *  Resource (or URL) node in the ARP tree.
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */


import java.io.*;
import java.util.*;
import java.security.acl.*;

public class ArpResource extends ArpCore implements Serializable{

    // Attributes
    protected String name;

    // Associations
    protected TName tName;
    protected Vector attributes;
    protected AA_Acl acl;

    // constructor
    public ArpResource(String name) throws NotOwnerException{
	this.name = name;
	tName = new TName(name);
	attributes = new Vector();
	makeAcl("resourceAcl");
    }

    // Operations
    public String toString() {
	return name+" ["+tName+"]";
    }


    public boolean addAnAttribute(String name, boolean exclude)
	throws AAPermissionException{

	if(attributes.contains(new ArpAttribute(name, exclude)))
	    return false; // already there
	if(! insertPermitted())
	    throw new AAPermissionException("No INSERT right for "+getCaller());
	attributes.add(new ArpAttribute(name, exclude));
	return true;
    }

    public boolean addAnAttribute(ArpAttribute attr)
	throws AAPermissionException{
	return addAnAttribute(attr, false);
    }

    /**
     * Adds the given attribute to the attributes for this Resource.
     * if force flag is true and attribute already exists
     * then replaces the existing reource otherwise leaves the existing 
     * attribute untouched.  
     * returns false if reource already existed.
     */
    public boolean addAnAttribute(ArpAttribute attr, boolean force)
	throws AAPermissionException {

	if(attributes.contains(attr)){
	    if(force){
		if(! replacePermitted())
		    throw new AAPermissionException("No replace right for "+getCaller());		
		attributes.remove(attr);
		attributes.add(attr);
	    }
	    return false; // already there
	}
	if(! insertPermitted())
	    throw new AAPermissionException("No INSERT right for "+getCaller());	
	attributes.add(attr);
	return true;
    }

    public boolean removeAnAttribute(String name)
	throws AAPermissionException {

	if(attributes.contains(new ArpAttribute(name, false))){
	    if(! insertPermitted())
		throw new AAPermissionException("No DELETE right for "+getCaller());	    
	    attributes.remove(new ArpAttribute(name, false));
	    return true;
	}
	return false; // not found
    }

    public ArpAttribute getAttribute(String name) {
	Enumeration en = attributes.elements();
	while(en.hasMoreElements()){
	    ArpAttribute aAttribute = (ArpAttribute)en.nextElement();
	    if(aAttribute.getName().equals(name))
		return aAttribute;
	}
	return null;
    }

    public ArpAttribute[] getAttributes() {
	int len = attributes.size();
	ArpAttribute[] a = new ArpAttribute[len];
	for(int i = 0; i < len; i++)
	    a[i] = (ArpAttribute)attributes.get(i);
	return a;
    }


    public int fit(String resrcName) {
	TName tn = new TName(resrcName);
	return tName.compare(tn);
    }

    public TName getTName(){
	return tName;
    }

    public String getName(){
	return name;
    }

    public boolean equals(Object rsrc){
	return name.equals(((ArpResource)rsrc).getName());
    }

} /* end class ArpResource */
