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

import edu.internet2.middleware.shibboleth.aa.arp.MatchFunction;
import edu.internet2.middleware.shibboleth.aa.arp.MatchingException;

import org.apache.log4j.Logger;

import java.net.MalformedURLException;
import java.net.URL;

/**
 * MatchFuction implementation that does "tail" matching on resources.
 * 
 * @author Walter Hoehn (wassa&#064;columbia.edu)
 */
public class ResourceTreeMatchFunction implements MatchFunction {

	private static Logger log = Logger.getLogger(ResourceTreeMatchFunction.class.getName());

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.arp.MatchFunction#match(Object, Object)
	 */
	public boolean match(Object arpComponent, Object requestComponent) throws MatchingException {

		if (!(arpComponent instanceof String) || !(requestComponent instanceof URL)) {
			log.error("Invalid use of ARP matching function (ResourceTreeMatchFunction).");
			throw new MatchingException("Invalid use of ARP matching function (ResourceTreeMatchFunction).");
		}

		URL arpURL = null;

		try {
			arpURL = new URL((String) arpComponent);
		} catch (MalformedURLException e) {
			log.error("Invalid use of ARP matching function (ResourceTreeMatchFunction): ARP Component is not a URL.");
			throw new MatchingException("Invalid use of ARP matching function (ResourceTreeMatchFunction).");
		}

		if (!matchProtocol(arpURL, (URL) requestComponent)) { return false; }

		if (!matchHost(arpURL, (URL) requestComponent)) { return false; }

		if (!matchPort(arpURL, (URL) requestComponent)) { return false; }

		if (!matchPath(arpURL, (URL) requestComponent)) { return false; }

		if (!matchQuery(arpURL, (URL) requestComponent)) { return false; }

		return true;
	}

	protected boolean matchHost(URL arpURL, URL requestURL) {

		return arpURL.getHost().equals(requestURL.getHost());
	}

	protected boolean matchPath(URL arpURL, URL requestURL) {

		String arpPath = arpURL.getPath();

		if (arpPath.equals("")) {
			arpPath = "/";
		}

		String requestPath = requestURL.getPath();

		if (requestPath.equals("")) {
			requestPath = "/";
		}

		return requestPath.startsWith(arpPath);
	}

	protected boolean matchPort(URL arpURL, URL requestURL) {

		int arpPort = arpURL.getPort();

		if (arpPort < 1) {
			arpPort = arpURL.getDefaultPort();
		}

		int requestPort = requestURL.getPort();

		if (requestPort < 1) {
			requestPort = requestURL.getDefaultPort();
		}

		if (arpPort == requestPort) { return true; }

		return false;
	}

	protected boolean matchProtocol(URL arpURL, URL requestURL) {

		return arpURL.getProtocol().equals(requestURL.getProtocol());
	}

	protected boolean matchQuery(URL arpURL, URL requestURL) {

		if (arpURL.getQuery() == null) { return true; }

		return arpURL.getQuery().equals(requestURL.getQuery());
	}
}
