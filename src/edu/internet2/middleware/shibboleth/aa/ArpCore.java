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
 *  Core structure for all ARP nodes
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */


import java.util.Enumeration;
import java.security.Principal;
import java.security.acl.*;
import java.io.Serializable;

public class ArpCore implements Serializable{

    // Attributes
    protected String userEnv = "user.name";
    protected Acl acl;

    // Associations

    // Constructors


    // Operations
    public Principal getCaller(){
	// return new KerberosPrincipal(System.getProperty(userEnv));
	return new AA_Identity(System.getProperty(userEnv));
    }

    public void makeAcl(String name)throws NotOwnerException{
	Principal owner = getCaller();
	acl = new AA_Acl(name, owner);
	AclEntry entry = new AA_AclEntry(owner);
	entry.addPermission(new AA_Permission(AA_Permission.ALL));
	acl.addEntry(owner, entry);
    }


    public Acl getAcl(){
	return acl;
    }

    public void setAcl(String user, String permit)
	throws AAPermissionException, NotOwnerException{

	Principal prince = new AA_Identity(user);
	if(permit.equalsIgnoreCase("NONE")){
	    setAcl(prince, null);
	    return;
	}
	String[] permitNames = AA_Permission.names;
	for(int i=0; i < permitNames.length; i++){
	    if(permitNames[i].equalsIgnoreCase(permit)){
		setAcl(prince, new AA_Permission(i));
		return;
	    }
	}
	throw new AAPermissionException("No such ACL: "+permit);
    }

    public void setAcl(Principal user, Permission permit)
	throws NotOwnerException, AAPermissionException{

	if(!setAclPermitted())
	    throw new AAPermissionException("ALL access is needed to set ACL.");
	if(permit == null){
	    AclEntry entry = getAclEntry(user);
	    if(entry == null)
		throw new AAPermissionException("No ACL entry found for user: "+user);
	    if(!acl.removeEntry(getCaller(), entry))
		throw new AAPermissionException("No ACL entry found. System Eror");
	    return;
	}

	if(acl.checkPermission(user, permit))
	    return; // already has it
	AclEntry entry = getAclEntry(user);
	if(entry == null){
	    entry = new AA_AclEntry(user);
	    entry.addPermission(permit);
	    acl.addEntry(getCaller(), entry);
	}else{
	    entry.addPermission(permit);
	}
	return;
    }

    private AclEntry getAclEntry(Principal user){
	AclEntry entry = null;

	Enumeration en = acl.entries();
	while(en.hasMoreElements()){
	    entry = (AclEntry)en.nextElement();
	    if(entry.getPrincipal().equals(user))
		return entry;
	}
	return null;
    }

	
    /**
     * Check to see if caller has permission to remove and insert (i.e replace) for this object.
     * Returns true if permitted.
     */
    
    public boolean replacePermitted(){
	Permission rm = new AA_Permission(AA_Permission.DELETE);
	Permission add = new AA_Permission(AA_Permission.INSERT);
	Principal user = getCaller();
	if(acl.checkPermission(user, rm) && acl.checkPermission(user, add))
	    return true;
	return false;
    }

    public boolean insertPermitted(){
	Permission add = new AA_Permission(AA_Permission.INSERT);
	if(acl.checkPermission(getCaller(), add))
	    return true;
	return false;
    }

    public boolean removePermitted(){
	Permission rm = new AA_Permission(AA_Permission.DELETE);
	if(acl.checkPermission(getCaller(), rm))
	    return true;
	return false;
    }

    public boolean setAclPermitted(){
	Permission all = new AA_Permission(AA_Permission.ALL);
	if(acl.checkPermission(getCaller(), all))
	    return true;
	return false;
    }


	    


} /* end class ArpCore */
