package edu.internet2.middleware.shibboleth.aa;

import java.io.*;
import java.util.*;
import javax.naming.directory.*;

public class ArpAttribute implements Serializable{

    // Attributes
    protected String ID;
    protected boolean exclude;

    // Associations
    protected ArpFilter filter;

    // Constructor
    public ArpAttribute(String ID, boolean exclude){
	this.ID = ID;
	this.exclude = exclude;
    }

    // Operations
    public Attribute getDirAttribute(DirContext ctx, boolean doFilter)
	throws javax.naming.NamingException{

	String[] ids = new String[1];
	ids[0] = ID;
	Attributes attrs = ctx.getAttributes("", ids);
	Attribute attr = attrs.get(ID);

	if(doFilter && hasFilter()){
	    ArpFilterValue[] fvArray = filter.getFilterValues();
	    for(int i=0; i < fvArray.length; i++){
		if(fvArray[i].mustInclude())
		    ; //skip. do not filter.
		else
		    attr.remove(fvArray[i].getValue());
	    }
	}
	return attr;
    }


    public String getName(){
	return ID;
    }

    /**
     * lists all known attribute names.  Probably by consulting a 
     * database or LDAP schemas
     */
    public String[] list(){
	return null;
    }

    public boolean hasFilter(){
	if(filter == null)
	    return false;
	return true;
    }

    public ArpFilter getFilter(){
	return filter;
    }

    /**
     * sets a filter for this attribute.  returns true if succeeds
     * returns false if there is already a filter set.
     * If flag Force is true it replaces the existing filter,
     * otherwise does not replace the existing filter.
     */
    public boolean setFilter(ArpFilter filter, boolean force){
	if(hasFilter()){
	    if(force)
		this.filter = filter;
	    return false;
	}
	this.filter = filter;
	return true;
    }
    
    public boolean mustExclude(){
	return exclude;
    }

    public boolean equals(Object attr){
	return ID.equals(((ArpAttribute)attr).getName());
    }

    public int hashCode(){
	return ID.hashCode();
    }

    public String toString(){
	return ID+(exclude?"(exclude)":"");
    }

} /* end class ArpAttribute */
