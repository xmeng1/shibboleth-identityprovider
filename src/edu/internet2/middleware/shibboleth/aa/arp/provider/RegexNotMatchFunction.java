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

import java.net.URL;

import edu.internet2.middleware.shibboleth.aa.arp.MatchFunction;
import edu.internet2.middleware.shibboleth.aa.arp.MatchingException;

import org.apache.log4j.Logger;

/**
 * Match function implementaiton that matches when a given regular expression does NOT match.
 * 
 * @author Walter Hoehn (wassa&#064;columbia.edu)
 */
public class RegexNotMatchFunction implements MatchFunction {

	private static Logger log = Logger.getLogger(RegexNotMatchFunction.class.getName());

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.arp.MatchFunction#match(Object, Object)
	 */
	public boolean match(Object arpComponent, Object requestComponent) throws MatchingException {

		if (!(arpComponent instanceof String)
				|| !(requestComponent instanceof String || requestComponent instanceof URL)) {
			log.error("Invalid use of ARP matching function (RegexMatchFunction).");
			throw new MatchingException("Invalid use of ARP matching function (RegexMatchFunction).");
		}
		if (requestComponent instanceof URL) { return ((URL) requestComponent).toString()
				.matches((String) arpComponent); }
		return !((String) requestComponent).matches((String) arpComponent);
	}
}
