package edu.internet2.middleware.shibboleth.wayf;

import java.util.ArrayList;

/**
 * This class is used to create logical groupings of shibboleth Origin Sites.
 * Each grouping is associated with a textual name that might be displayed 
 * in a UI to accommodate user selection.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class OriginSet {

	private ArrayList origins = new ArrayList();
	;
	private String name;

	/**
	 * Gets the name.
	 * @return Returns a String
	 */
	public String getName() {
		return name;
	}

	/**
	 * Sets the name.
	 * @param name The name to set
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * Gets the origins.
	 * @return Returns a Origin[]
	 */
	public Origin[] getOrigins() {
		return (Origin[]) origins.toArray(new Origin[0]);
	}

	/**
	 * Sets the origins.
	 * @param origins The origins to set
	 */
	public void addOrigin(Origin origin) {
		origins.add(origin);
	}

}
