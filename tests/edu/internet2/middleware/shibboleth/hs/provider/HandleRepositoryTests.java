/* 
 * The Shibboleth License, Version 1. 
 * Copyright (c) 2002 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
 * 
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this 
 * list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution, if any, must include 
 * the following acknowledgment: "This product includes software developed by 
 * the University Corporation for Advanced Internet Development 
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement 
 * may appear in the software itself, if and wherever such third-party 
 * acknowledgments normally appear.
 * 
 * Neither the name of Shibboleth nor the names of its contributors, nor 
 * Internet2, nor the University Corporation for Advanced Internet Development, 
 * Inc., nor UCAID may be used to endorse or promote products derived from this 
 * software without specific prior written permission. For written permission, 
 * please contact shibboleth@shibboleth.org
 * 
 * Products derived from this software may not be called Shibboleth, Internet2, 
 * UCAID, or the University Corporation for Advanced Internet Development, nor 
 * may Shibboleth appear in their name, without prior written permission of the 
 * University Corporation for Advanced Internet Development.
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK 
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY 
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.hs.provider;

import java.io.File;
import java.net.MalformedURLException;
import java.util.Date;
import java.util.Properties;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;
import edu.internet2.middleware.shibboleth.hs.HandleRepository;
import edu.internet2.middleware.shibboleth.hs.HandleRepositoryException;
import edu.internet2.middleware.shibboleth.hs.HandleRepositoryFactory;

/**
 * Validation suite for the <code>HandleRepository</code> implementations.
 * 
 * @ author Walter Hoehn(wassa@columbia.edu)
 */

public class HandleRepositoryTests extends TestCase {

	private static Logger log = Logger.getLogger(HandleRepositoryTests.class.getName());

	public HandleRepositoryTests(String name) {
		super(name);
		BasicConfigurator.resetConfiguration();
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	public static void main(String[] args) {
		junit.textui.TestRunner.run(HandleRepositoryTests.class);
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.OFF);
	}

	/**
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		super.setUp();
	}

	public void testBasicCryptoRepository() {

		try {
			Properties props = new Properties();
			File file = new File("data/handle.jks");

			props.setProperty(
				"edu.internet2.middleware.shibboleth.hs.HandleRepository.implementation",
				"edu.internet2.middleware.shibboleth.hs.provider.CryptoHandleRepository");
			props.setProperty(
				"edu.internet2.middleware.shibboleth.hs.provider.CryptoHandleRepository.keyStorePath",
				file.toURL().toString());
			props.setProperty(
				"edu.internet2.middleware.shibboleth.hs.provider.CryptoHandleRepository.keyStorePassword",
				"shibhs");
			props.setProperty(
				"edu.internet2.middleware.shibboleth.hs.provider.CryptoHandleRepository.keyStoreKeyAlias",
				"handleKey");
			props.setProperty(
				"edu.internet2.middleware.shibboleth.hs.provider.CryptoHandleRepository.keyStoreKeyPassword",
				"shibhs");
			props.setProperty("edu.internet2.middleware.shibboleth.hs.BaseHandleRepository.handleTTL", "1800");

			HandleRepository repository = HandleRepositoryFactory.getInstance(props);

			Date beforeGeneration = new Date();
			StringBuffer format = new StringBuffer();
			String handle = repository.getHandle(new AuthNPrincipal("foo"), format);
			Date afterGeneration = new Date();

			Date beforeMarshalling = new Date();
			AuthNPrincipal principal = repository.getPrincipal(handle, format.toString());
			assertEquals("Round-trip handle validation failed.", principal.getName(), "foo");
			Date afterMarshalling = new Date();

			log.debug("Before Handle Generation: " + beforeGeneration + "-" + beforeGeneration.getTime());
			log.debug("After Handle Generation:  " + afterGeneration + "-" + afterGeneration.getTime());
			log.debug("Before Handle Marshalling: " + beforeMarshalling + "-" + beforeMarshalling.getTime());
			log.debug("After Handle Marshalling:  " + afterMarshalling + "-" + afterMarshalling.getTime());

		} catch (MalformedURLException e) {
			fail("Error in test specification: " + e.getMessage());
		} catch (HandleRepositoryException e) {
			fail("Error exercising Handle Repository: " + e.getMessage());
		}
	}

}
