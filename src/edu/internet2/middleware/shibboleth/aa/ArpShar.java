package aa;

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
