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
