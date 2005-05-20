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
			for (int i = 0; (i < newOrigins.length); i++) {
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
				for (int i = 0; (i < origins.length); i++) {
					if (originName.equals(origins[i].getName())) { return origins[i].getHandleService(); }
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
			for (int i = 0; (i < origins.length); i++) {
				if (origins[i].isMatch(searchString, config)) {
					searchResults.add(origins[i]);
				}
			}
		}
		return (Origin[]) searchResults.toArray(new Origin[0]);
	}

}
