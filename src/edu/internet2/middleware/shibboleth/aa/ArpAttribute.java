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
 *  Attribute node in ARP tree.
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */


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
