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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;

import org.apache.log4j.Logger;

/**
 * This class is a container for OriginSets, allowing lookup and searching of the same.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class WayfOrigins {

	private HashMap origins = new HashMap();
	private static Logger log = Logger.getLogger(WayfOrigins.class.getName());

	public OriginSet[] getOriginSets() {
		return (OriginSet[]) origins.values().toArray(new OriginSet[0]);
	}

	public void addOriginSet(OriginSet originSet) {
		if (origins.containsKey(originSet.getName())) {
			OriginSet previousOrigins = (OriginSet) origins.get(originSet.getName());
			Origin[] newOrigins = originSet.getOrigins();
			for (int i = 0;(i < newOrigins.length); i++) {
				previousOrigins.addOrigin(newOrigins[i]);
			}
		} else {
			origins.put(originSet.getName(), originSet);
		}
		log.debug("Adding origin set :" + originSet.getName() + ": to configuration");
	}

	public String lookupHSbyName(String originName) {
		if (originName != null) {
			Iterator originSetIt = origins.values().iterator();
			while (originSetIt.hasNext()) {

				OriginSet originSet = (OriginSet) originSetIt.next();
				Origin[] origins = originSet.getOrigins();
				for (int i = 0;(i < origins.length); i++) {
					if (originName.equals(origins[i].getName())) {
						return origins[i].getHandleService();
					}
				}
			}

		}
		return null;

	}

	public Origin[] seachForMatchingOrigins(String searchString, WayfConfig config) {

		Iterator originSetIt = origins.values().iterator();
		HashSet searchResults = new HashSet();
		while (originSetIt.hasNext()) {

			OriginSet originSet = (OriginSet) originSetIt.next();
			Origin[] origins = originSet.getOrigins();
			for (int i = 0;(i < origins.length); i++) {
				if (origins[i].isMatch(searchString, config)) {
					searchResults.add(origins[i]);
				}
			}
		}
		return (Origin[]) searchResults.toArray(new Origin[0]);
	}

}
