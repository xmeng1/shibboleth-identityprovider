package edu.internet2.middleware.shibboleth.aa;

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





