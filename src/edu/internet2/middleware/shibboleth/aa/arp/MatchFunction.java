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

package edu.internet2.middleware.shibboleth.aa.arp;

/**
 * Defines an method for determining whether an ARP Rule is applicable to a particular request
 * 
 * @author Walter Hoehn (wassa&#064;columbia.edu)
 */
public interface MatchFunction {

	/**
	 * Boolean indication of whether the specified ARP component matches the specified Request component. Used to
	 * determine if an ARP is applicable to a particular request.
	 */
	public boolean match(Object arpComponent, Object requestComponent) throws MatchingException;
}
