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
 
package edu.internet2.middleware.shibboleth.utils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;

/**
 * Generates a Triple DES key and sticks it in the default location for use by 
 * the <code>CryptoHandleRepository</code>
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public class HandleRepositorySecretGenerator extends Task {

	private File keyStorePath;
	private String keyStorePassword;
	private String keyStoreKeyAlias;
	private String keyStoreKeyPassword;
	public void execute() throws BuildException {
		try {
			if (keyStorePath == null
				|| keyStorePassword == null
				|| keyStoreKeyAlias == null
				|| keyStoreKeyPassword == null) {
				throw new BuildException("Missing required parameter.");
			}
			log("Generating secret.");
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
			byte[] pseudoRand = new byte[24];
			new SecureRandom().nextBytes(pseudoRand);
			SecretKey secret = keyFactory.generateSecret(new DESedeKeySpec(pseudoRand));

			log("Writing keystore.");
			KeyStore keyStore = KeyStore.getInstance("JCEKS");
			keyStore.load(null, keyStorePassword.toCharArray());
			keyStore.setKeyEntry(keyStoreKeyAlias, secret, keyStoreKeyPassword.toCharArray(), null);
			keyStore.store(new FileOutputStream(keyStorePath), keyStorePassword.toCharArray());

		} catch (GeneralSecurityException e) {
			throw new BuildException("Unable to generate secret: " + e);
		} catch (IOException e) {
			throw new BuildException("Unable to store secret in keystore: " + e);
		}
	}

	/**
	 * Sets the keyStoreKeyAlias.
	 * @param keyStoreKeyAlias The keyStoreKeyAlias to set
	 */
	public void setKeyStoreKeyAlias(String keyStoreKeyAlias) {
		this.keyStoreKeyAlias = keyStoreKeyAlias;
	}

	/**
	 * Sets the keyStoreKeyPassword.
	 * @param keyStoreKeyPassword The keyStoreKeyPassword to set
	 */
	public void setKeyStoreKeyPassword(String keyStoreKeyPassword) {
		this.keyStoreKeyPassword = keyStoreKeyPassword;
	}

	/**
	 * Sets the keyStorePassword.
	 * @param keyStorePassword The keyStorePassword to set
	 */
	public void setKeyStorePassword(String keyStorePassword) {
		this.keyStorePassword = keyStorePassword;
	}

	/**
	 * Sets the keyStorePath.
	 * @param keyStorePath The keyStorePath to set
	 */
	public void setKeyStorePath(File keyStorePath) {
		this.keyStorePath = keyStorePath;
	}

}
