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

import java.util.Arrays;
import java.util.SortedSet;
import java.util.TreeSet;

import org.apache.log4j.Logger;

/**
 * This class is used to create logical groupings of shibboleth Origin Sites. Each grouping is associated with a textual
 * name that might be displayed in a UI to accommodate user selection.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class OriginSet {

	private SortedSet origins = new TreeSet();
	private static Logger log = Logger.getLogger(OriginSet.class.getName());
	private String name = "";

	public String getName() {

		return name;
	}

	public void setName(String name) {

		this.name = name;
	}

	public Origin[] getOrigins() {

		Origin[] result = (Origin[]) origins.toArray(new Origin[0]);
		Arrays.sort(result);
		return result;
	}

	public void addOrigin(Origin origin) {

		if (origin.getHandleService() != null) {
			origins.add(origin);
			log.debug("Adding origin site :" + origin.getName() + ":  to set.");
		}
	}

}
