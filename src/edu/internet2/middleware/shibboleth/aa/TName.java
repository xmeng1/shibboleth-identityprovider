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
 *  Tokenized form of a resource.
 *
 * @author     Parviz Dousti (dousti@cmu.edu)
 * @created    June, 2002
 */

import java.io.*;
import java.util.*;
class TName implements Serializable{

    // Attributes
    private String name;
    private String[] tokens;
    final static String WILD = "*";

    // Associations
    protected ArpResource myArpResource;

    // Constructors
    /** 
     * This class is a tokenized reprezentation of a URL so 
     * URLs can be compared against each other and see what is
     * the best match or best fit.
     */
    TName(String url){
	// break down the url and store it in a String[]
	if(url.startsWith("http://"))
	    url = url.substring(7);
	if(url.startsWith("https://"))
	    url = url.substring(8);

	int i = 0;
	StringTokenizer slash = new StringTokenizer(url, ":/\\");
	if(slash.hasMoreTokens()){
	    // first element generally host name
	    String hostname = slash.nextToken();
	    StringTokenizer dot = new StringTokenizer(hostname, ".");
	    int count = dot.countTokens();
	    tokens = new String[count+slash.countTokens()];
	    for(int n = count; n > 0;  n--){
		tokens[n-1] = dot.nextToken();
	    }
	    i += count;
	}
	while(slash.hasMoreTokens()){
	    tokens[i++] = slash.nextToken();
	}
    }

    // Operations
    public String[] getTokens() {
	return tokens;
    }

    public int compare(TName t){
	String[] gTokens = t.getTokens();
	int len = tokens.length;
	int glen = gTokens.length;
	if(len == 0 || glen == 0)
	    return 0;
	for(int i=0; i<Math.min(len, glen); i++){
	    if(tokens[i].equalsIgnoreCase(gTokens[i]))
		continue;
	    if(tokens[i].equals(WILD) || gTokens[i].equals(WILD))
		continue;
	    return 0;
	}
	return Math.min(len,glen);
    }
    
    public String toString(){
	StringBuffer buf = new StringBuffer();
	int len =tokens.length;
	for(int i = 0; i < len-1; i++){
	    buf.append(tokens[i]);
	    buf.append(", ");
	}
	if(len > 0)
	    buf.append(tokens[len-1]); // add the last one
	return buf.toString();
    }
} /* end class TName */
