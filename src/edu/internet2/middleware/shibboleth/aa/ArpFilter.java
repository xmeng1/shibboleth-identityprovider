package edu.internet2.middleware.shibboleth.aa;

/**
 *  Attribute Authority & Release Policy
 *  Filter node in the ARP tree.
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */


import java.io.*;
import java.util.*;
public class ArpFilter implements Serializable{


    // Associations
    protected Vector values;
    
    // Constructor
    public ArpFilter(){
	values = new Vector();
    }

    // Operations
    public ArpFilterValue[] getFilterValues() {
	ArpFilterValue[] afva = new ArpFilterValue[values.size()];
	return (ArpFilterValue[])values.toArray(afva);
    }

    public boolean addAFilterValue(ArpFilterValue afv) {
	return addAFilterValue(afv, false);
    }

    /**
     * Adds the given value to the values for this Filter.
     * if force flag is true and value already exists
     * then replaces the existing reource otherwise leaves the existing 
     * value untouched.  
     * returns false if reource already existed.
     */
    public boolean addAFilterValue(ArpFilterValue afv, boolean force) {
	if(values.contains(afv)){
	    if(force){
		values.remove(afv);
		values.add(afv);
	    }
	    return false; // already there
	}
	values.add(afv);
	return true;
    }

    public boolean removeFilterValue(ArpFilterValue afv) {
	if(values.contains(afv)){
	    values.remove(afv);
	    return true;
	}
	return false; // not found
    }

    public boolean contains(ArpFilterValue afv) {
	return values.contains(afv);
    }

    public ArpFilterValue[] getInclusions() {
	Vector incs = new Vector();
	Enumeration en = values.elements();
	while(en.hasMoreElements()){
	    ArpFilterValue afv = (ArpFilterValue)en.nextElement();
	    if(afv.mustInclude())
		incs.add(afv);
	}
	return (ArpFilterValue[])incs.toArray();
    }
 
    
    public String toString(){
	StringBuffer buf = new StringBuffer();
	Enumeration en = values.elements();
	while(en.hasMoreElements()){
	    buf.append((ArpFilterValue)en.nextElement());
	    buf.append(", ");
	}
	return buf.toString();
    }
	

} /* end class ArpFilter */
