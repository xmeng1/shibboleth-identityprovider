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
 *  Shar node in ARP tree.
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */

import java.io.*;
import java.util.*;
import java.security.acl.*;

public class ArpShar extends ArpCore implements Serializable{

    // Attributes
    protected String name;
    protected boolean isDefault;

    // Associations
    protected Vector  resources;
    protected AA_Acl acl;

    // Construstor
    public ArpShar(String name, boolean isDefault)throws NotOwnerException{
	this.name = name;
	this.isDefault = isDefault;
	resources  = new Vector();
	makeAcl("sharAcl");
    }

    // Operations
    public String toString() {
	return name+(isDefault?"(default)":"");
    }

    public boolean isDefault(){
	return isDefault;
    }

    public boolean addAResource(String url)
	throws NotOwnerException,AAPermissionException{

	if(resources.contains(new ArpResource(url)))
	    return false; // already there

	if(! insertPermitted())
	    throw new AAPermissionException("No INSERT right for "+getCaller());

	resources.add(new ArpResource(url));
	return true;
    }

    /**
     * Adds a given resource to the resources for this Shar.
     * Does not replace if resource already exists.
     * returns false if resource already exists.
     */

    public boolean addAResource(ArpResource rsrc) 
	throws AAPermissionException{
	return addAResource(rsrc, false);
    }

    /**
     * Adds the given resource to the resources for this Shar.
     * if force flag is true and resource already exists
     * then replaces the existing reource otherwise leaves the existing 
     * resource untouched.  
     * returns false if reource already existed.
     */
    public boolean addAResource(ArpResource rsrc, boolean force)
	throws AAPermissionException{

	if(resources.contains(rsrc)){
	    if(force){
		if(! replacePermitted())
		    throw new AAPermissionException("No replace right for "+getCaller());
		resources.remove(rsrc);
		resources.add(rsrc);
	    }
	    return false; // already there
	}
	if(! insertPermitted())
	    throw new AAPermissionException("No INSERT right for "+getCaller());
	resources.add(rsrc);
	return true;
    }

    public boolean removeAResource(String url)
	throws NotOwnerException, AAPermissionException{
	if(resources.contains(new ArpResource(url))){
	    if(! removePermitted())
		throw new AAPermissionException("No DELETE right for "+getCaller());
	    resources.remove(new ArpResource(url));
	    return true;
	}
	return false; // not found
    }

    public ArpResource getResource(String url) {
	Enumeration en = resources.elements();
	while(en.hasMoreElements()){
	    ArpResource aResource = (ArpResource)en.nextElement();
	    if(aResource.getName().equals(url))
		return aResource;
	}
      	return null;
    }

    public ArpResource[] getResources() {
	int len = resources.size();
	ArpResource[] a = new ArpResource[len];
	for(int i = 0; i < len; i++)
	    a[i] = (ArpResource)resources.get(i);
	return a;
    }


    /**
     * Go throu all resource objects and find the one that
     * best matches the given url.  This is based on comparison 
     * of TNames of urls provided by fit method of ArpResource.
     *
     * returns an ArpResource or null if no match found;
     */
    public ArpResource bestFit(String url) {

	ArpResource[] ara = new ArpResource[resources.size()];
	ara = (ArpResource[])resources.toArray(ara);
	int bestScore = 0;
	ArpResource bestResource = null;
	for(int i=0; i < ara.length; i++){
	    int score =  ara[i].fit(url);
	    if(score > bestScore){
		bestScore = score;
		bestResource = ara[i];
	    }
	}
	return bestResource;
    }

    public String getName(){
	return name;
    }

    public boolean equals(Object shar){
	return name.equals(((ArpShar)shar).getName());
    }

} /* end class ArpShar */
