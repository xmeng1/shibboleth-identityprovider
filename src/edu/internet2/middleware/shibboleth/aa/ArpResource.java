package edu.internet2.middleware.shibboleth.aa;

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
