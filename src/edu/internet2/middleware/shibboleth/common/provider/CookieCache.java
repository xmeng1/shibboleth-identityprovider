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

package edu.internet2.middleware.shibboleth.common.provider;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import edu.internet2.middleware.shibboleth.common.Cache;
import edu.internet2.middleware.shibboleth.utils.Base32;

/**
 * <code>Cache</code> implementation that uses browser cookies to store data. Symmetric and HMAC algorithms are used
 * to encrypt and verify the data. Due to the size limitations of cookie storage, data may interleaved among multiple
 * cookies.
 * 
 * @author Walter Hoehn
 */
public class CookieCache extends BaseCache implements Cache {

	// TODO domain limit?
	private HttpServletResponse response;
	private List<Cookie> myCurrentCookies = new ArrayList<Cookie>();
	private Map<String, CacheEntry> dataCache = new HashMap<String, CacheEntry>();
	private static final int CHUNK_SIZE = 4 * 1024; // in KB, minimal browser requirement
	private static final int COOKIE_LIMIT = 20; // minimal browser requirement
	private static final String NAME_PREFIX = "IDP_CACHE:";
	protected SecretKey secret;
	private static SecureRandom random = new SecureRandom();
	private String cipherAlgorithm = "DESede/CBC/PKCS5Padding";
	private String macAlgorithm = "HmacSHA1";
	private String storeType = "JCEKS";

	CookieCache(String name, HttpServletRequest request, HttpServletResponse response) {

		super(name, Cache.CacheType.CLIENT_SIDE);
		this.response = response;
		Cookie[] requestCookies = request.getCookies();
		for (int i = 0; i < requestCookies.length; i++) {
			if (requestCookies[i].getName().startsWith(NAME_PREFIX)) {
				myCurrentCookies.add(requestCookies[i]);
			}
		}

		// TODO dechunk, decrypt, and pull in dataCache
	}

	public boolean contains(String key) {

		CacheEntry entry = dataCache.get(key);

		if (entry == null) { return false; }

		// Clean cache if it is expired
		if (new Date().after(((CacheEntry) entry).expiration)) {
			deleteFromCache(key);
			return false;
		}

		// OK, we have it
		return true;
	}

	private void deleteFromCache(String key) {

		dataCache.remove(key);
		flushCache();
	}

	public Object retrieve(String key) {

		CacheEntry entry = dataCache.get(key);

		if (entry == null) { return null; }

		// Clean cache if it is expired
		if (new Date().after(((CacheEntry) entry).expiration)) {
			deleteFromCache(key);
			return null;
		}

		// OK, we have it
		return entry.value;
	}

	public void store(String key, String value, long duration) {

		dataCache.put(key, new CacheEntry(value, duration));
		flushCache();
	}

	/**
	 * Secures, encodes, and writes out (to cookies) cached data.
	 */
	private void flushCache() {

		// TODO create String representation of all cache data
		String stringData = null;

		try {

			// Setup a gzipped data stream
			ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
			GZIPOutputStream compressedStream = new GZIPOutputStream(byteStream);
			DataOutputStream dataStream = new DataOutputStream(compressedStream);

			// Write data and HMAC to stream
			Mac mac = Mac.getInstance(macAlgorithm);
			mac.init(secret);
			dataStream.write(mac.doFinal(stringData.getBytes()));
			dataStream.writeUTF(stringData);

			// Flush
			dataStream.flush();
			compressedStream.flush();
			compressedStream.finish();
			byteStream.flush();

			// Setup encryption lib
			Cipher cipher = Cipher.getInstance(cipherAlgorithm);
			byte[] iv = new byte[cipher.getBlockSize()];
			random.nextBytes(iv);
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			cipher.init(Cipher.ENCRYPT_MODE, secret, ivSpec);

			// Creat byte array of IV and encrypted cache
			byte[] encryptedData = cipher.doFinal(byteStream.toByteArray());
			byte[] cacheBytes = new byte[iv.length + encryptedData.length];
			// Write IV
			System.arraycopy(iv, 0, cacheBytes, 0, iv.length);
			// Write encrypted cache
			System.arraycopy(encryptedData, 0, cacheBytes, iv.length, encryptedData.length);

			// Base32 encode
			String encodedData = Base32.encode(cacheBytes);

			// Put into cookies
			interleaveInCookies(encodedData);

		} catch (KeyException e) {
			// TODO handle
		} catch (GeneralSecurityException e) {
			// TODO handle
		} catch (IOException e) {
			// TODO handle
		}
	}

	/**
	 * Writes encoded data across multiple cookies
	 */
	private void interleaveInCookies(String data) {

		// Convert the String data to a list of cookies
		List<Cookie> cookiesToResponse = new ArrayList<Cookie>();
		StringBuffer bufferredData = new StringBuffer(data);
		while (bufferredData != null && bufferredData.length() > 0) {
			Cookie cookie = null;
			String name = null;
			if (bufferredData.length() <= getCookieSpace()) {
				cookie = new Cookie(name, bufferredData.toString());
				bufferredData = null;
			} else {
				cookie = new Cookie(name, bufferredData.substring(0, getCookieSpace() - 1));
				bufferredData.delete(0, getCookieSpace() - 1);
			}
			cookiesToResponse.add(cookie);
		}

		// We have to null out cookies that are no longer needed
		for (Cookie previousCookie : myCurrentCookies) {
			if (!cookiesToResponse.contains(previousCookie)) {
				cookiesToResponse.add(new Cookie(previousCookie.getName(), null));
			}
		}

		// Write our cookies to the response object
		for (Cookie cookie : cookiesToResponse) {
			response.addCookie(cookie);
		}

		// Update our cached copy of the cookies
		myCurrentCookies = cookiesToResponse;
	}

	/**
	 * Returns the amount of value space available in cookies we create
	 */
	private int getCookieSpace() {

		// TODO this needs to be better
		return 3000;
	}

}
