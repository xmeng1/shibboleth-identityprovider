/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.wayf;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.StringTokenizer;

/**
 * This class represents an Origin site in the shibboleth parlance.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class Origin implements Comparable {

	private String name = "";
	private ArrayList aliases = new ArrayList();
	private String handleService = "";

	/**
	 * Gets the handleService for this origin.
	 * 
	 * @return Returns a String
	 */
	public String getHandleService() {

		return handleService;
	}

	/**
	 * Sets the handleService for this origin.
	 * 
	 * @param handleService
	 *            The handleService to set
	 */
	public void setHandleService(String handleService) {

		this.handleService = handleService;
	}

	/**
	 * Gets the origin name.
	 * 
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
	 * 
	 * @param name
	 *            The name to set
	 */
	public void setName(String name) {

		this.name = name;
	}

	/**
	 * Gets all aliases for this origin.
	 * 
	 * @return Returns a String[]
	 */
	public String[] getAliases() {

		return (String[]) aliases.toArray(new String[0]);
	}

	/**
	 * Adds an alias for this origin.
	 * 
	 * @param alias
	 *            The aliases to set
	 */
	public void addAlias(String alias) {

		aliases.add(alias);
	}

	/**
	 * Determines if a given string matches one of the registered names/aliases of this origin.
	 * 
	 * @param str
	 *            The string to match on
	 */
	public boolean isMatch(String str, WayfConfig config) {

		Enumeration input = new StringTokenizer(str);
		while (input.hasMoreElements()) {
			String currentToken = (String) input.nextElement();

			if (config.isIgnoredForMatch(currentToken)) {
				continue;
			}

			if (getName().toLowerCase().indexOf(currentToken.toLowerCase()) > -1) { return true; }
			Iterator aliasit = aliases.iterator();
			while (aliasit.hasNext()) {
				String alias = (String) aliasit.next();
				if (alias.toLowerCase().indexOf(currentToken.toLowerCase()) > -1) { return true; }
			}

		}
		return false;
	}

	/**
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	public int compareTo(Object o) {

		int result = getDisplayName().toLowerCase().compareTo(((Origin) o).getDisplayName().toLowerCase());
		if (result == 0) {
			result = getDisplayName().compareTo(((Origin) o).getDisplayName());
		}
		return result;
	}

}