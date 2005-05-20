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

package edu.internet2.middleware.shibboleth.aa.arp.provider;

import org.apache.log4j.Logger;

import edu.internet2.middleware.shibboleth.aa.arp.MatchFunction;
import edu.internet2.middleware.shibboleth.aa.arp.MatchingException;

/**
 * Match function that matches strings that are not the same.
 * 
 * @author Walter Hoehn (wassa&#064;columbia.edu)
 */
public class StringValueNotMatchFunction implements MatchFunction {

	private static Logger log = Logger.getLogger(StringValueNotMatchFunction.class.getName());

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.arp.MatchFunction#match(Object, Object)
	 */
	public boolean match(Object arpComponent, Object requestComponent) throws MatchingException {

		if (!(arpComponent instanceof String) || !(requestComponent instanceof String)) {
			log.error("Invalid use of ARP matching function (StringValueNotMatchFunction).");
			throw new MatchingException("Invalid use of ARP matching function (StringValueNotMatchFunction).");
		}
		return !arpComponent.equals(requestComponent);
	}
}
