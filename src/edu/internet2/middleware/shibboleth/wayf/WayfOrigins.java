package edu.internet2.middleware.shibboleth.wayf;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;

import org.apache.log4j.Logger;

/**
 * This class is a container for OriginSets, allowing lookup and searching of the same.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class WayfOrigins {

	private ArrayList originSets = new ArrayList();
	private static Logger log = Logger.getLogger(WayfOrigins.class.getName());

	public OriginSet[] getOriginSets() {
		return (OriginSet[]) originSets.toArray(new OriginSet[0]);
	}

	public void addOriginSet(OriginSet originSet) {
		originSets.add(originSet);
		log.debug("Adding an origin set to configuration");
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

	public Origin[] seachForMatchingOrigins(String searchString, WayfConfig config) {

		Iterator originSetIt = originSets.iterator();
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
