package edu.internet2.middleware.shibboleth.aa;

import java.util.*;
import java.io.*;
import java.security.acl.*;

public class AA_Acl implements java.security.acl.Acl, Serializable{

    HashSet positives;
    HashSet negatives;
    HashSet owners;
    String name;

    AA_Acl(String name, java.security.Principal root){
	positives = new HashSet();
	negatives = new HashSet();
	owners = new HashSet();
	this.name = name;
	owners.add(root);
    }

    AA_Acl(Collection p, Collection n, String name, java.security.Principal root){
	positives = new HashSet(p);
	negatives = new HashSet(n);
	owners = new HashSet();
	this.name = name;
	owners.add(root);
    }

    /////// Methods //////////

    public boolean addEntry(java.security.Principal p, AclEntry entry)throws NotOwnerException{

	if(this.isOwner(p) == false)
	    throw new NotOwnerException();
	if(entry.isNegative()){
	    if(negatives.contains(entry)){
		return false;
	    }else{
		negatives.add(entry);
		return true;
	    }
	}else{  // is positive ACL
	    if(positives.contains(entry)){
		return false;
	    }else{
		positives.add(entry);
		return true;
	    }
	}
    }

    public boolean checkPermission(java.security.Principal user, java.security.acl.Permission perm){
	for(Iterator it = positives.iterator(); it.hasNext();){
	    AclEntry entry = (AclEntry)it.next();
	    java.security.Principal p = entry.getPrincipal();
	    if(p.equals(user)){
		if(entry.checkPermission(perm)){
		    //make sure it is not in negative list
		    for(Iterator it2 = negatives.iterator(); it2.hasNext();){
			AclEntry entry2 = (AclEntry)it2.next();
			java.security.Principal p2 = entry2.getPrincipal();
			if(p2.equals(user)){
			    if(entry2.checkPermission(perm)){
				return false; // in both list
			    }
			    continue;
			}
		    }
		    // not in negative list
		    return true;  // give permission
		}else{
		    continue;
		}
	    }else{
		continue;
	    }
	}
	return false;  // not in any positive entry
    }

    public Enumeration entries(){
	return new AclEntryEnumeration(positives, negatives);
    }

    public String getName(){
	return name;
    }

    public Enumeration getPermissions(java.security.Principal user){
	return new AclPermissionEnumeration(user, positives, negatives);
    }

    public boolean removeEntry(java.security.Principal caller, AclEntry entry)
    throws NotOwnerException{
	
	if(this.isOwner(caller) == false)
	    throw new NotOwnerException();
	if(entry.isNegative()){
	    if(negatives.contains(entry)){
		negatives.remove(entry);
		return true;
	    }else{
		return false;
	    }
	}else{  // is positive ACL
	    if(positives.contains(entry)){
		positives.remove(entry);
		return true;
	    }else{
		return false;
	    }
	}
    }


    public void setName(java.security.Principal caller, String name)
	throws NotOwnerException{
	if(this.isOwner(caller) == false)
	    throw new NotOwnerException();
	this.name = name;
    }

    public String toString(){
	return name+
	    "{"
	    +positives
	    +"}{"
	    +negatives
	    +"}";

    }

    /////////// Owner methods ///////////////
    public boolean addOwner(java.security.Principal caller, java.security.Principal owner)
	throws NotOwnerException{
	if(owners.contains(caller) == false)
	    throw new NotOwnerException();
	return owners.add(owner);
    }

    public boolean deleteOwner(java.security.Principal caller, java.security.Principal owner)
	throws NotOwnerException,
        LastOwnerException{
	if(owners.contains(caller) == false)
	    throw new NotOwnerException();
	return owners.remove(owner);	
    }

    public boolean isOwner(java.security.Principal owner){
	return owners.contains(owner);
    }
	
    
}
 
class AclEntryEnumeration implements java.util.Enumeration{
    HashSet entries;
    Iterator it;

    AclEntryEnumeration(HashSet p, HashSet n){
	entries = p;
	entries.addAll(n);  
	it = entries.iterator();
    }

    public boolean hasMoreElements(){
	return it.hasNext();
    }

    public Object nextElement(){
	return it.next();
    }
}



class AclPermissionEnumeration implements java.util.Enumeration{
    HashSet permissions;
    Iterator it;

    AclPermissionEnumeration(java.security.Principal user, HashSet p, HashSet n){
	permissions = new HashSet();
	// go throu entries and find the one for this user
	for(Iterator i = p.iterator(); i.hasNext();){
	    AclEntry ae = (AclEntry)i.next();
	    if(ae.getPrincipal().equals(user)){
		// go throu permissions and add it to enum
		for(Enumeration j=ae.permissions(); j.hasMoreElements();){
		    permissions.add((Permission)j.nextElement());
		}
	    }
	}
	// now go throu negatives and either add it or remove positve one
	for(Iterator i = n.iterator(); i.hasNext();){
	    AclEntry ae = (AclEntry)i.next();
	    if(ae.getPrincipal().equals(user)){
		// go throu permissions and check it
		for(Enumeration j=ae.permissions(); j.hasMoreElements();){
		    Permission perm = (Permission)j.nextElement();
		    if(permissions.contains(perm)){
			permissions.remove(perm);
		    }else{
			permissions.add(perm);
		    }
		}
	    }
	}

	it = permissions.iterator();
    }

    public boolean hasMoreElements(){
	return it.hasNext();
    }

    public Object nextElement(){
	return it.next();
    }
}





