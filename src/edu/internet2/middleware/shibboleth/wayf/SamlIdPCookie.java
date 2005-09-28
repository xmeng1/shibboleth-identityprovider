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

import java.util.ArrayList;
import java.util.Iterator;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.util.encoders.Base64;

/**
 * Implementation of the <code>_saml_idp </code> cookie.
 * 
 * Note that any SamlIdPCookie is only valid for as long as the reqest/response 
 * parameters provided to getIdPCookie remain valid.
 * 
 * @author Rod Widdowson
 *
 */
public class SamlIdPCookie  {

	private static final String COOKIE_NAME = "_saml_idp";

	private final HttpServletRequest req;
	private final HttpServletResponse res;
	private final String domain;
	private final ArrayList /*<String>*/ idPList = new ArrayList/*<String>*/();
	
	/**
	 * Constructs a <code>SamlIdPCookie</code> from the provided string (which is the raw data 
	 * 
	 * @param codedData
	 *            the information read from the cookie
	 * @param domain - if non null the domain for any *created* cookie.
	 */
	private SamlIdPCookie(String codedData, HttpServletRequest req, HttpServletResponse res, String domain) {
		
		this.req = req;
		this.res = res;
		this.domain = domain;
		
		int start;
		int end;
		
		if (codedData == null || codedData.equals("")) {
			return;
		}
		//
		// Because there are spaces in the data the cookie may be returned enclosed in quotes
		//
		if (codedData.charAt(0) == '"' && codedData.charAt(codedData.length()-1) == '"') {
			codedData= codedData.substring(1,codedData.length()-1);
		}
		
		
		start = 0;
		end = codedData.indexOf(' ', start);
		while (end > 0) {
			String value = codedData.substring(start, end);
			start = end + 1;
			end = codedData.indexOf(' ', start);
			if (!value.equals("")) {
			    idPList.add(new String(Base64.decode(value)));
			}
		}
		if (start < codedData.length()) {
			String value = codedData.substring(start);
			if (!value.equals("")) {
			    idPList.add(new String(Base64.decode(value)));
			}
		}
	}
	/**
	 * Create a SamlCookie with no data inside.
	 * @param domain - if non null, the domain of the new cookie 
	 *
	 */
	public SamlIdPCookie(HttpServletRequest req, HttpServletResponse res, String domain) {
		this.req = req;
		this.res = res;
		this.domain = domain;
	}

	/**
	 * Add the specified Shibboleth IdP Name to the cookie list or move to 
	 * the front and then write it back.
	 * 
	 * We always add to the front (and remove from wherever it was)
	 * 
	 * @param idPName    - The name to be added
	 * @param expiration - The expiration of the cookie or zero if it is to be unchanged
	 */
	public void addIdPName(String idPName, int expiration) {

		idPList.remove(idPName);
		idPList.add(0, idPName);

		writeCookie(expiration);
	}

	/**
	 * Return an iterator over the list of IdPNames 
	 * @param which
	 * @return
	 */

	public Iterator/*<String>*/ iterator() {

		return idPList.iterator();
	}
	
	/**
	 * Delete the <b>entire<\b> cookie contents
	 */

	public static void deleteCookie(HttpServletRequest req, HttpServletResponse res) {
		Cookie cookie = getCookie(req);
		
		if (cookie == null) { 
			return; 
		}
		cookie.setMaxAge(0);
		res.addCookie(cookie);
	}

	/**
	 * Load up the cookie and convert it into a SamlIdPCookie.  If there is no
	 * underlying cookie return a null one.
	 * @param domain - if this is set then any <b>created</b> cookies are set to this domain 
	 */
	
	public static SamlIdPCookie getIdPCookie(HttpServletRequest req, HttpServletResponse res, String domain) {
		Cookie cookie = getCookie(req);
		
		if (cookie == null) {
			return new SamlIdPCookie(req, res, domain);
		} else {
			return new SamlIdPCookie(cookie.getValue(), req, res, domain);
		}
	}

	/**
	 * Remove origin from the cachedata and write it back.
	 * @param origin
	 */
	
	public void deleteIdPName(String origin) {
		idPList.remove(origin);
		writeCookie(0);
	}

	private void writeCookie(int expiration)
	{
		Cookie cookie = getCookie(req);
		
		if (idPList.size() == 0) {
			//
			// Nothing to write, so delete the cookie
			//
			cookie.setMaxAge(0);
			res.addCookie(cookie);
			return;
		}

		//
		// Otherwise encode up the cookie
		//
		
		StringBuffer buffer = new StringBuffer();
		Iterator /*<String>*/ it = idPList.iterator();
		
		while (it.hasNext()) {
			String next = (String) it.next();
			String what = new String(Base64.encode(next.getBytes()));
			buffer.append(what).append(' ');
		}
		
		String value = buffer.toString();
		
		if (cookie == null) { 
			cookie = new Cookie(COOKIE_NAME, value);
		} else {
			cookie.setValue(value);
		}
		cookie.setComment("Used to cache selection of a user's Shibboleth IdP");
		cookie.setPath("/");

		if (expiration > 0) {
			cookie.setMaxAge(expiration);
		}
		if (domain != null && domain != "") {
			cookie.setDomain(domain);
		}
		res.addCookie(cookie);
	
	}

	private static Cookie getCookie(HttpServletRequest req) {
		
		Cookie[] cookies = req.getCookies();
		if (cookies != null) {
			for (int i = 0; i < cookies.length; i++) {
				if (cookies[i].getName().equals(COOKIE_NAME)) { 
					return cookies[i];
				}
			}
		}
		return null;
	}
}
