package edu.internet2.middleware.shibboleth.wayf;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;

/**
 * This class is a container for OriginSets, allowing lookup and searching of the same.
 * @author		Walter Hoehn
 */

public class WayfOrigins {

	private ArrayList originSets = new ArrayList();

	public OriginSet[] getOriginSets() {
		return (OriginSet[]) originSets.toArray(new OriginSet[0]);
	}

	public void addOriginSet(OriginSet originSet) {
		originSets.add(originSet);
	}

	public String lookupHSbyName(String originName) {
		if (originName != null) {
			Iterator originSetIt = originSets.iterator();
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

	public Origin[] seachForMatchingOrigins(String searchString) {

		Iterator originSetIt = originSets.iterator();
		HashSet searchResults = new HashSet();
		while (originSetIt.hasNext()) {

			OriginSet originSet = (OriginSet) originSetIt.next();
			Origin[] origins = originSet.getOrigins();
			for (int i = 0;(i < origins.length); i++) {
				if (origins[i].isMatch(searchString)) {
					searchResults.add(origins[i]);
				}
			}
		}
		return (Origin[]) searchResults.toArray(new Origin[0]);
	}

}
