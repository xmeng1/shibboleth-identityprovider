package edu.internet2.middleware.shibboleth.wayf;

import java.util.ArrayList;
import java.util.HashSet;

import org.apache.log4j.Logger;

/**
 * This class is used to create logical groupings of shibboleth Origin Sites.
 * Each grouping is associated with a textual name that might be displayed 
 * in a UI to accommodate user selection.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class OriginSet {

	private HashSet origins = new HashSet();
	private static Logger log = Logger.getLogger(OriginSet.class.getName());
	private String name = "";


	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public Origin[] getOrigins() {
		return (Origin[]) origins.toArray(new Origin[0]);
	}

	public void addOrigin(Origin origin) {
		origins.add(origin);
		log.debug("Adding origin site :"+ origin.getName() + ":  to set.");
	}

}
