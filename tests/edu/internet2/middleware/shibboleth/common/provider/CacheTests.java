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

import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.Cookie;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import com.mockrunner.mock.web.MockHttpServletRequest;
import com.mockrunner.mock.web.MockHttpServletResponse;
import com.mockrunner.mock.web.WebMockObjectFactory;

import edu.internet2.middleware.shibboleth.common.Cache;
import edu.internet2.middleware.shibboleth.common.CacheException;
import edu.internet2.middleware.shibboleth.common.CredentialsTests;

public class CacheTests extends TestCase {

	private static Logger log = Logger.getLogger(CacheTests.class.getName());
	private WebMockObjectFactory factory = new WebMockObjectFactory();
	private MockHttpServletResponse response = factory.getMockResponse();
	private MockHttpServletRequest request = factory.getMockRequest();

	private String cipherAlgorithm = "DESede/CBC/PKCS5Padding";
	private String macAlgorithm = "HmacSHA1";

	byte[] defaultKey = new byte[]{(byte) 0xC7, (byte) 0x49, (byte) 0x80, (byte) 0xD3, (byte) 0x02, (byte) 0x4A,
			(byte) 0x61, (byte) 0xEF, (byte) 0x25, (byte) 0x5D, (byte) 0xE3, (byte) 0x2F, (byte) 0x57, (byte) 0x51,
			(byte) 0x20, (byte) 0x15, (byte) 0xC7, (byte) 0x49, (byte) 0x80, (byte) 0xD3, (byte) 0x02, (byte) 0x4A,
			(byte) 0x61, (byte) 0xEF};

	public CacheTests(String name) {

		super(name);
		BasicConfigurator.resetConfiguration();
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	public static void main(String[] args) {

		junit.textui.TestRunner.run(CredentialsTests.class);
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	/**
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {

		super.setUp();
		request.resetAll();
		response.resetAll();
	}

	public void testServletSessionCache() {

		try {
			// Startup the cache
			Cache cache = new ServletSessionCache("foobar", request);

			// Make sure the cache starts clean
			assertNull("Cache contained errant record.", cache.retrieve("foo"));

			// Store and retrieve
			cache.store("foo", "bar", 99999);
			assertTrue("Cache expected to contain record.", cache.contains("foo"));
			assertEquals("Cache expected to contain record.", "bar", cache.retrieve("foo"));

			// Make sure expiration works
			cache.store("bar", "foo", 1);
			try {
				Thread.sleep(2000);
			} catch (InterruptedException e) {
				// Who cares
			}
			assertFalse("Cache expected to expire record.", cache.contains("bar"));
			assertEquals("Cache expected to expire record.", null, cache.retrieve("bar"));

		} catch (CacheException e) {
			fail("Error exercising cache: " + e);
		}
	}

	public void testMemoryCache() {

		try {
			// Startup the cache
			Cache cache = new MemoryCache("foobar");

			// Make sure the cache starts clean
			assertNull("Cache contained errant record.", cache.retrieve("foo"));

			// Store and retrieve
			cache.store("foo", "bar", 99999);
			assertTrue("Cache expected to contain record.", cache.contains("foo"));
			assertEquals("Cache expected to contain record.", "bar", cache.retrieve("foo"));

			// Make sure expiration works
			cache.store("bar", "foo", 1);
			try {
				Thread.sleep(2000);
			} catch (InterruptedException e) {
				// Who cares
			}
			assertFalse("Cache expected to expire record.", cache.contains("bar"));
			assertEquals("Cache expected to expire record.", null, cache.retrieve("bar"));

		} catch (CacheException e) {
			fail("Error exercising cache: " + e);
		}
	}

	public void testCookieCacheBasic() {

		try {

			SecretKey secret = new SecretKeySpec(defaultKey, "DESede");

			// Startup the cache
			CookieCache cache = new CookieCache("foobar", secret, cipherAlgorithm, macAlgorithm, request, response);

			// Make sure the cache starts clean
			assertNull("Cache contained errant record.", cache.retrieve("foo"));

			// Store and retrieve
			cache.store("foo", "bar", 99999);
			assertTrue("Cache expected to contain record.", cache.contains("foo"));
			assertEquals("Cache expected to contain record.", "bar", cache.retrieve("foo"));

			// Make sure expiration works
			cache.store("expr1", "foo", 1); // check immediate
			cache.store("expr2", "foo", 1); // check after round trip

			try {
				Thread.sleep(2000);
			} catch (InterruptedException e) {
				// Who cares
			}
			assertFalse("Cache expected to expire record.", cache.contains("expr1"));
			assertEquals("Cache expected to expire record.", null, cache.retrieve("expr1"));

			// Write cache to cookies
			cache.postProcessing();
			request.resetAll();

			// Round trip testing
			// Add cookies from previous query response to the new request.. to simulate a browser interaction
			List<Cookie> cookies = (List<Cookie>) response.getCookies();
			for (Cookie cookie : cookies) {
				log.debug("Cookie Name: " + cookie.getName());
				log.debug("Cookie Value: " + cookie.getValue());
				request.addCookie(cookie);
			}

			response.resetAll();

			cache = new CookieCache("foobar", secret, cipherAlgorithm, macAlgorithm, request, response);

			// Test round-tripped entry
			assertTrue("Cache expected to contain record.", cache.contains("foo"));
			assertEquals("Cache expected to contain record.", "bar", cache.retrieve("foo"));

			// Test round-tripped expired entry
			assertFalse("Cache expected to expire record.", cache.contains("expr2"));
			assertEquals("Cache expected to expire record.", null, cache.retrieve("expr2"));

		} catch (CacheException e) {
			fail("Error exercising cache: " + e);
		}
	}

	public void testCookieCacheLargeDataSet() {

		try {

			SecretKey secret = new SecretKeySpec(defaultKey, "DESede");

			// Round trip with a large data set
			CookieCache cache = new CookieCache("foobar", secret, cipherAlgorithm, macAlgorithm, request, response);
			for (int i = 0; i < 5000; i++) {
				cache.store(new Integer(i).toString(), "Walter", 99999);
			}

			cache.postProcessing();
			request.resetAll();

			List<Cookie> cookies = (List<Cookie>) response.getCookies();
			for (Cookie cookie : cookies) {
				log.debug("Cookie Name: " + cookie.getName());
				log.debug("Cookie Value: " + cookie.getValue());
				request.addCookie(cookie);
			}

			response.resetAll();

			cache = new CookieCache("foobar", secret, cipherAlgorithm, macAlgorithm, request, response);
			assertEquals("Cache expected to contain record.", "Walter", cache.retrieve(new Integer(1).toString()));

		} catch (CacheException e) {
			fail("Error exercising cache: " + e);
		}
	}

	public void testCookieCacheStaleCookieCleanup() {

		try {

			SecretKey secret = new SecretKeySpec(defaultKey, "DESede");

			// Round trip with a large data set
			CookieCache cache = new CookieCache("foobar", secret, cipherAlgorithm, macAlgorithm, request, response);
			for (int i = 0; i < 5000; i++) {
				cache.store(new Integer(i).toString(), "Walter", 99999);
			}

			cache.postProcessing();
			request.resetAll();

			List<Cookie> cookies = (List<Cookie>) response.getCookies();
			for (Cookie cookie : cookies) {
				log.debug("Cookie Name: " + cookie.getName());
				log.debug("Cookie Value: " + cookie.getValue());
				log.debug("Cookie Max Age: " + cookie.getMaxAge());
				request.addCookie(cookie);
			}

			response.resetAll();
			cache = new CookieCache("foobar", secret, cipherAlgorithm, macAlgorithm, request, response);

			// OK, delete a bunch of entries and make sure this is reflected in the cookies
			for (int i = 0; i < 4999; i++) {
				cache.remove(new Integer(i).toString());
			}

			cache.postProcessing();
			request.resetAll();

			cookies = (List<Cookie>) response.getCookies();
			for (Cookie cookie : cookies) {
				log.debug("Cookie Name: " + cookie.getName());
				log.debug("Cookie Value: " + cookie.getValue());
				log.debug("Cookie Max Age: " + cookie.getMaxAge());
				request.addCookie(cookie);
				if (!cookie.getName().equals("IDP_CACHE:foobar:1")) {
					assertTrue("Cookie not properly expired.", cookie.getMaxAge() == 0);
				}
			}

		} catch (CacheException e) {
			fail("Error exercising cache: " + e);
		}
	}

}
