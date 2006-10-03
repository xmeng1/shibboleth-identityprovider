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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import edu.internet2.middleware.shibboleth.common.Cache;
import edu.internet2.middleware.shibboleth.common.CacheException;
import edu.internet2.middleware.shibboleth.utils.Base32;

/**
 * <code>Cache</code> implementation that uses browser cookies to store data. Symmetric and HMAC algorithms are used
 * to encrypt and verify the data. Due to the size limitations of cookie storage, data may interleaved among multiple
 * cookies. NOTE: Using this cache implementation in a standalon tomcat configuration will usually require that the
 * "maxHttpHeaderSize" parameter be greatly increased.
 * 
 * @author Walter Hoehn
 */
public class CookieCache extends BaseCache implements Cache {

	private static Logger log = Logger.getLogger(CookieCache.class.getName());
	private HttpServletResponse response;
	private Collection<Cookie> myCurrentCookies = new ArrayList<Cookie>();
	private Map<String, CacheEntry> dataCache = new HashMap<String, CacheEntry>();
	private static final int CHUNK_SIZE = 4 * 1024; // minimal browser requirement
	private static final int COOKIE_LIMIT = 20; // minimal browser requirement
	private static final String NAME_PREFIX = "IDP_CACHE:";
	private static int totalCookies = 0;
	protected SecretKey secret;
	private static SecureRandom random = new SecureRandom();
	private String cipherAlgorithm;
	private String macAlgorithm;

	public CookieCache(String name, SecretKey key, String cipherAlgorithm, String macAlgorithm,
			HttpServletRequest request, HttpServletResponse response) throws CacheException {

		super(name, Cache.CacheType.CLIENT_SIDE);
		this.secret = key;
		this.cipherAlgorithm = cipherAlgorithm;
		this.macAlgorithm = macAlgorithm;
		this.response = response;
		Cookie[] requestCookies = request.getCookies();
		if (requestCookies != null) {
			for (int i = 0; i < requestCookies.length; i++) {
				if (requestCookies[i].getName().startsWith(NAME_PREFIX + getName())
						&& requestCookies[i].getValue() != null) {
					myCurrentCookies.add(requestCookies[i]);
				}
			}
		}

		if (usingDefaultSecret()) {
			log.warn("You are running the Cookie Cache with the "
					+ "default secret key.  This is UNSAFE!  Please change "
					+ "this configuration and restart the IdP.");
		}

		initFromCookies();
	}

	public void postProcessing() throws CacheException {

		if (totalCookies > (COOKIE_LIMIT - 1)) {
			log.warn("The Cookie Cache mechanism is about to write a large amount of data to the "
					+ "client.  This may not work with some browser software, so it is recommended"
					+ " that you investigate other caching mechanisms.");
		}

		flushCache();
	}

	public boolean contains(String key) throws CacheException {

		CacheEntry entry = dataCache.get(key);

		if (entry == null) { return false; }

		// Clean cache if it is expired
		if (new Date().after(((CacheEntry) entry).expiration)) {
			log.debug("Found expired object.  Deleting...");
			totalCookies--;
			dataCache.remove(key);
			return false;
		}

		// OK, we have it
		return true;
	}

	public String retrieve(String key) throws CacheException {

		CacheEntry entry = dataCache.get(key);

		if (entry == null) { return null; }

		// Clean cache if it is expired
		if (new Date().after(((CacheEntry) entry).expiration)) {
			log.debug("Found expired object.  Deleting...");
			totalCookies--;
			dataCache.remove(key);
			return null;
		}

		// OK, we have it
		return entry.value;
	}

	public void remove(String key) throws CacheException {

		dataCache.remove(key);
		totalCookies--;
	}

	public void store(String key, String value, long duration) throws CacheException {

		dataCache.put(key, new CacheEntry(value, duration));
		totalCookies++;
	}

	private void initFromCookies() throws CacheException {

		log.debug("Attempting to initialize cache from client-supplied cookies.");
		// Pull data from cookies
		List<Cookie> relevantCookies = new ArrayList<Cookie>();
		for (Cookie cookie : myCurrentCookies) {
			if (cookie.getName().startsWith(NAME_PREFIX + getName())) {
				relevantCookies.add(cookie);
			}
		}
		if (relevantCookies.isEmpty()) {
			log.debug("No applicable cookies found.  Cache is empty.");
			return;
		}

		// Sort
		String[] sortedCookieValues = new String[relevantCookies.size()];
		for (Cookie cookie : relevantCookies) {
			String[] tokenizedName = cookie.getName().split(":");
			sortedCookieValues[Integer.parseInt(tokenizedName[tokenizedName.length - 1]) - 1] = cookie.getValue();
		}
		// Concatenate
		StringBuffer concat = new StringBuffer();
		for (String cookieValue : sortedCookieValues) {
			concat.append(cookieValue);
		}
		log.debug("Dumping Encrypted/Encoded Input Cache: " + concat);

		try {
			// Decode Base32
			byte[] in = Base32.decode(concat.toString());

			// Decrypt
			Cipher cipher = Cipher.getInstance(cipherAlgorithm);
			int ivSize = cipher.getBlockSize();
			byte[] iv = new byte[ivSize];
			Mac mac = Mac.getInstance(macAlgorithm);
			mac.init(secret);
			int macSize = mac.getMacLength();
			if (in.length < ivSize) {
				log.error("Cache is malformed (not enough bytes).");
				throw new CacheException("Cache is malformed (not enough bytes).");
			}

			// extract the IV, setup the cipher and extract the encrypted data
			System.arraycopy(in, 0, iv, 0, ivSize);
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			cipher.init(Cipher.DECRYPT_MODE, secret, ivSpec);
			byte[] encryptedData = new byte[in.length - iv.length];
			System.arraycopy(in, ivSize, encryptedData, 0, in.length - iv.length);

			// decrypt the rest of the data andsetup the streams
			byte[] decryptedBytes = cipher.doFinal(encryptedData);
			ByteArrayInputStream byteStream = new ByteArrayInputStream(decryptedBytes);
			GZIPInputStream compressedData = new GZIPInputStream(byteStream);
			ObjectInputStream dataStream = new ObjectInputStream(compressedData);

			// extract the components
			byte[] decodedMac = new byte[macSize];

			int bytesRead = dataStream.read(decodedMac);
			if (bytesRead != macSize) {
				log.error("Error parsing cache: Unable to extract HMAC.");
				throw new CacheException("Error parsing cache: Unable to extract HMAC.");
			}

			String decodedData = (String) dataStream.readObject();
			log.debug("Dumping Raw Input Cache: " + decodedData);

			// Verify HMAC
			byte[] generatedMac = mac.doFinal(decodedData.getBytes());
			if (!Arrays.equals(decodedMac, generatedMac)) {
				log.error("Cookie cache data failed integrity  check.");
				throw new GeneralSecurityException("Cookie cache data failed integrity check.");
			}

			// Parse XML
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			factory.setNamespaceAware(false);
			Element cacheElement = factory.newDocumentBuilder().parse(new InputSource(new StringReader(decodedData)))
					.getDocumentElement();
			NodeList items = cacheElement.getElementsByTagName("Item");
			for (int i = 0; i < items.getLength(); i++) {
				Element item = (Element) items.item(i);
				totalCookies++;
				dataCache.put(item.getAttribute("key"), new CacheEntry(item.getAttribute("value"), new Date(new Long(
						item.getAttribute("expire")))));
			}

		} catch (Exception e) {
			log.error("Error decrypting cache data: " + e);
			throw new CacheException("Unable to read cached data.");
		}
	}

	private boolean usingDefaultSecret() {

		byte[] defaultKey = new byte[]{(byte) 0xC7, (byte) 0x49, (byte) 0x80, (byte) 0xD3, (byte) 0x02, (byte) 0x4A,
				(byte) 0x61, (byte) 0xEF, (byte) 0x25, (byte) 0x5D, (byte) 0xE3, (byte) 0x2F, (byte) 0x57, (byte) 0x51,
				(byte) 0x20, (byte) 0x15, (byte) 0xC7, (byte) 0x49, (byte) 0x80, (byte) 0xD3, (byte) 0x02, (byte) 0x4A,
				(byte) 0x61, (byte) 0xEF};
		byte[] encodedKey = secret.getEncoded();
		return Arrays.equals(defaultKey, encodedKey);
	}

	/**
	 * Secures, encodes, and writes out (to cookies) cached data.
	 */
	private void flushCache() throws CacheException {

		log.debug("Flushing cache.");
		log.debug("Encrypting cache data.");

		// Create XML/String representation of all cache data
		String stringData = null;

		try {

			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			docFactory.setNamespaceAware(false);
			Document placeHolder = docFactory.newDocumentBuilder().newDocument();

			Element cacheNode = placeHolder.createElement("Cache");
			for (Entry<String, CacheEntry> entry : dataCache.entrySet()) {
				Element itemNode = placeHolder.createElement("Item");
				itemNode.setAttribute("key", entry.getKey());
				itemNode.setAttribute("value", entry.getValue().value);
				itemNode.setAttribute("expire", new Long(entry.getValue().expiration.getTime()).toString());
				cacheNode.appendChild(itemNode);
			}

			TransformerFactory factory = TransformerFactory.newInstance();
			DOMSource source = new DOMSource(cacheNode);
			Transformer transformer = factory.newTransformer();
			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			StringWriter stringWriter = new StringWriter();
			StreamResult result = new StreamResult(stringWriter);
			transformer.transform(source, result);
			stringData = stringWriter.toString().replaceAll(">\\s<", "><");
			log.debug("Dumping Raw Cache: " + stringData);

		} catch (Exception e) {
			log.error("Error encoding cache data: " + e);
			throw new CacheException("Unable to cache data.");
		}

		try {

			// Setup a gzipped data stream
			ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
			GZIPOutputStream compressedStream = new GZIPOutputStream(byteStream);
			ObjectOutputStream dataStream = new ObjectOutputStream(compressedStream);

			// Write data and HMAC to stream
			Mac mac = Mac.getInstance(macAlgorithm);
			mac.init(secret);
			dataStream.write(mac.doFinal(stringData.getBytes()));
			dataStream.writeObject(stringData);

			// Flush
			// dataStream.flush();
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
			log.debug("Dumping Encrypted/Encoded Cache: " + encodedData);

			// Put into cookies
			interleaveInCookies(encodedData);

		} catch (Exception e) {
			log.error("Error encrypting cache data: " + e);
			throw new CacheException("Unable to cache data.");
		}
	}

	/**
	 * Writes encoded data across multiple cookies
	 */
	private void interleaveInCookies(String data) {

		log.debug("Writing cache to cookies.");

		// Convert the String data to a list of cookies
		Map<String, Cookie> cookiesToResponse = new HashMap<String, Cookie>();
		StringBuffer bufferredData = new StringBuffer(data);
		int i = 1;
		while (bufferredData != null && bufferredData.length() > 0) {
			Cookie cookie = null;
			String name = NAME_PREFIX + getName() + ":" + i++;
			if (bufferredData.length() <= getCookieSpace(name)) {
				cookie = new Cookie(name, bufferredData.toString());
				bufferredData = null;
			} else {
				cookie = new Cookie(name, bufferredData.substring(0, getCookieSpace(name) - 1));
				bufferredData.delete(0, getCookieSpace(name) - 1);
			}
			cookiesToResponse.put(cookie.getName(), cookie);
		}

		// Expire cookies that we used previously but no longer need
		for (Cookie currCookie : myCurrentCookies) {
			if (!cookiesToResponse.containsKey(currCookie.getName())) {
				currCookie.setMaxAge(0);
				currCookie.setValue(null);
				cookiesToResponse.put(currCookie.getName(), currCookie);
			}
		}

		// Write our cookies to the response object
		for (Cookie cookie : cookiesToResponse.values()) {
			response.addCookie(cookie);
		}

		// Update our cached copy of the cookies
		myCurrentCookies = cookiesToResponse.values();
	}

	/**
	 * Returns the amount of value space available in cookies we create
	 */
	private int getCookieSpace(String cookieName) {

		// If we add other cookie variables, we would need to adjust this algorithm appropriately
		StringBuffer used = new StringBuffer();
		used.append("Set-Cookie: ");
		used.append(cookieName + "=" + " ");
		System.err.println(CHUNK_SIZE - used.length() - 2);
		return CHUNK_SIZE - used.length() - 2;
	}

}
