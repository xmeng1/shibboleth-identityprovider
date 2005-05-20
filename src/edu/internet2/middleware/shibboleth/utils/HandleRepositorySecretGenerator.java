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
 * Generates a Triple DES key and sticks it in the default location for use by the <code>CryptoHandleRepository</code>
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
			if (keyStorePath == null || keyStorePassword == null || keyStoreKeyAlias == null
					|| keyStoreKeyPassword == null) { throw new BuildException("Missing required parameter."); }
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
	 * 
	 * @param keyStoreKeyAlias
	 *            The keyStoreKeyAlias to set
	 */
	public void setKeyStoreKeyAlias(String keyStoreKeyAlias) {

		this.keyStoreKeyAlias = keyStoreKeyAlias;
	}

	/**
	 * Sets the keyStoreKeyPassword.
	 * 
	 * @param keyStoreKeyPassword
	 *            The keyStoreKeyPassword to set
	 */
	public void setKeyStoreKeyPassword(String keyStoreKeyPassword) {

		this.keyStoreKeyPassword = keyStoreKeyPassword;
	}

	/**
	 * Sets the keyStorePassword.
	 * 
	 * @param keyStorePassword
	 *            The keyStorePassword to set
	 */
	public void setKeyStorePassword(String keyStorePassword) {

		this.keyStorePassword = keyStorePassword;
	}

	/**
	 * Sets the keyStorePath.
	 * 
	 * @param keyStorePath
	 *            The keyStorePath to set
	 */
	public void setKeyStorePath(File keyStorePath) {

		this.keyStorePath = keyStorePath;
	}

}
