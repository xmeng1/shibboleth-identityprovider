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

package edu.internet2.middleware.shibboleth.wayf;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.StringTokenizer;

import org.apache.log4j.Logger;

/**
 * This class represents an Origin site in the shibboleth parlance.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class Origin {

	private static Logger log = Logger.getLogger(Origin.class.getName());
    private String name = "";
    private ArrayList aliases = new ArrayList();
    private String handleService = "";

    /**
     * Gets the handleService for this origin.
     * @return Returns a String
     */
    public String getHandleService() {
        return handleService;
    }

    /**
     * Sets the handleService for this origin.
     * @param handleService The handleService to set
     */
    public void setHandleService(String handleService) {
        this.handleService = handleService;
    }

    /**
     * Gets the origin name.
     * @return Returns a String
     */
    public String getName() {
        return name;
    }
    
    public String getDisplayName() {
    	if (aliases.get(0) != null) {
    		return (String) aliases.get(0);
    	} else {
    		return getName();
    	}
    }

    public String getUrlEncodedName() throws UnsupportedEncodingException {

			return URLEncoder.encode(name, "UTF-8");
    }

    /**
     * Sets a name for this origin.
     * @param name The name to set
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Gets all aliases for this origin.
     * @return Returns a String[]
     */
    public String[] getAliases() {
        return (String[]) aliases.toArray(new String[0]);
    }

    /**
     * Adds an alias for this origin.
     * @param alias The aliases to set
     */
    public void addAlias(String alias) {
        aliases.add(alias);
    }

    /**
     * Determines if a given string matches one of the registered names/aliases of this origin.
     * @param str The string to match on
     */
    public boolean isMatch(String str, WayfConfig config) {

        Enumeration input = new StringTokenizer(str);
        while (input.hasMoreElements()) {
            String currentToken = (String) input.nextElement();

            if (config.isIgnoredForMatch(currentToken)) {
                continue;
            }

            if (getName().toLowerCase().indexOf(currentToken.toLowerCase()) > -1) {
                return true;
            }
            Iterator aliasit = aliases.iterator();
            while (aliasit.hasNext()) {
                String alias = (String) aliasit.next();
                if (alias.toLowerCase().indexOf(currentToken.toLowerCase()) > -1) {
                    return true;
                }
            }

        }
        return false;
    }

}