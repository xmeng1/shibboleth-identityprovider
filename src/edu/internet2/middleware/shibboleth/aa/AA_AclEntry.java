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
 *  Access Control List Entry for ARPs
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */

import java.util.*;
import java.io.*;
import java.security.acl.*;
import java.security.*;

public class AA_AclEntry implements java.security.acl.AclEntry, Serializable{

    HashSet permissions;
    boolean isNegative;
    Principal principal;

    AA_AclEntry(Principal p){
	permissions = new HashSet();
	isNegative = false;
	principal = p;
    }

    AA_AclEntry(Collection c, boolean n, Principal p){
	permissions = new HashSet(c);
	isNegative = n;
	principal = p;
    }

    /////// Methods //////////

    public boolean addPermission(java.security.acl.Permission p){
	return permissions.add(p);
    }

    public boolean checkPermission(java.security.acl.Permission p){
	if(permissions.contains(new AA_Permission(AA_Permission.ALL)))
	    return true;
	boolean rc = permissions.contains(p);
	return rc;
    }

    public Object clone(){
	return new AA_AclEntry(permissions, isNegative, principal);
    }

    public Principal getPrincipal(){
	return principal;
    }

    public boolean isNegative(){
	return isNegative;
    }

    public Enumeration permissions(){
	return new PermissionsEnumeration(permissions);
    }

    public boolean removePermission(java.security.acl.Permission p){
	return permissions.remove(p);
    }

    public void setNegativePermissions(){
	isNegative = true;
    }

    public boolean setPrincipal(Principal p){
	if(principal != null){
	    return false;
	}else{
	    principal = p;
	    return true;
	}
    }

    public String toString(){
	return (isNegative?"-":"+")
	    +principal
	    +"("
	    +permissions
	    +")";
    }

    public boolean equals(Object o){
	AclEntry ae = (AclEntry)o;
	if(this.principal.equals(ae.getPrincipal()) && 
	   (ae.isNegative() == isNegative))
	    return true;
	return false;
    }

    public int hashCode(){
	return principal.hashCode();
    }
	   
    
}

class PermissionsEnumeration implements java.util.Enumeration{
    HashSet perms;
    Iterator it;

    PermissionsEnumeration(HashSet p){
	perms = p;
	it = perms.iterator();
    }

    public boolean hasMoreElements(){
	return it.hasNext();
    }

    public Object nextElement(){
	return it.next();
    }
}





