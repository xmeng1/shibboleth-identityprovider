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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Properties;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.log4j.Logger;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;
import edu.internet2.middleware.shibboleth.common.Constants;
import edu.internet2.middleware.shibboleth.common.ShibResource;
import edu.internet2.middleware.shibboleth.hs.HandleRepository;
import edu.internet2.middleware.shibboleth.hs.HandleRepositoryException;
import edu.internet2.middleware.shibboleth.hs.InvalidHandleException;

/**
 * <code>HandleRepository</code> implementation that employs the use of a shard secret
 * in order to transmit identity information.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public class CryptoHandleRepository extends BaseHandleRepository implements HandleRepository {

	private static Logger log = Logger.getLogger(CryptoHandleRepository.class.getName());
	protected SecretKey secret;
	private SecureRandom random = new SecureRandom();
	
	public CryptoHandleRepository(Properties properties) throws HandleRepositoryException {
		super(properties);
		try {

			checkRequiredParams(properties);
			KeyStore keyStore = KeyStore.getInstance("JCEKS");

			keyStore.load(
				new ShibResource(
					properties.getProperty(
						"edu.internet2.middleware.shibboleth.hs.provider.CryptoHandleRepository.keyStorePath"),
					this.getClass())
					.getInputStream(),
				properties
					.getProperty("edu.internet2.middleware.shibboleth.hs.provider.CryptoHandleRepository.keyStorePassword")
					.toCharArray());
			secret =
				(SecretKey) keyStore.getKey(
					properties.getProperty(
						"edu.internet2.middleware.shibboleth.hs.provider.CryptoHandleRepository.keyStoreKeyAlias"),
					properties
						.getProperty("edu.internet2.middleware.shibboleth.hs.provider.CryptoHandleRepository.keyStoreKeyPassword")
						.toCharArray());

			//Before we finish initilization, make sure that things are working
			testEncryption();

			if (usingDefaultSecret()) {
				log.warn(
					"You are running the Crypto Handle Repository with the default secret key.  This is UNSAFE!  Please change "
						+ "this configuration and restart the origin.");
			}

		} catch (KeyStoreException e) {
			log.error(
				"An error occurred while loading the java keystore.  Unable to initialize Crypto Handle Repository: "
					+ e);
			throw new HandleRepositoryException("An error occurred while loading the java keystore.  Unable to initialize Crypto Handle Repository.");
		} catch (CertificateException e) {
			log.error(
				"The java keystore contained corrupted data.  Unable to initialize Crypto Handle Repository: " + e);
			throw new HandleRepositoryException("The java keystore contained corrupted data.  Unable to initialize Crypto Handle Repository.");
		} catch (NoSuchAlgorithmException e) {
			log.error(
				"Appropriate JCE provider not found in the java environment. Unable to initialize Crypto Handle Repository: "
					+ e);
			throw new HandleRepositoryException("Appropriate JCE provider not found in the java environment. Unable to initialize Crypto Handle Repository.");
		} catch (IOException e) {
			log.error(
				"An error accessing while loading the java keystore.  Unable to initialize Crypto Handle Repository: "
					+ e);
			throw new HandleRepositoryException("An error occurred while accessing the java keystore.  Unable to initialize Crypto Handle Repository.");
		} catch (UnrecoverableKeyException e) {
			log.error(
				"Secret could not be loaded from the java keystore.  Verify that the alias and password are correct: "
					+ e);
			throw new HandleRepositoryException("Secret could not be loaded from the java keystore.  Verify that the alias and password are correct. ");
		}
	}

	private boolean usingDefaultSecret() {
		byte[] defaultKey =
			new byte[] {
				(byte) 0xC7,
				(byte) 0x49,
				(byte) 0x80,
				(byte) 0xD3,
				(byte) 0x02,
				(byte) 0x4A,
				(byte) 0x61,
				(byte) 0xEF,
				(byte) 0x25,
				(byte) 0x5D,
				(byte) 0xE3,
				(byte) 0x2F,
				(byte) 0x57,
				(byte) 0x51,
				(byte) 0x20,
				(byte) 0x15,
				(byte) 0xC7,
				(byte) 0x49,
				(byte) 0x80,
				(byte) 0xD3,
				(byte) 0x02,
				(byte) 0x4A,
				(byte) 0x61,
				(byte) 0xEF };
		byte[] encodedKey = secret.getEncoded();
		return Arrays.equals(defaultKey, encodedKey);
	}

	private void checkRequiredParams(Properties params) throws HandleRepositoryException {
		StringBuffer missingProperties = new StringBuffer();
		String[] requiredProperties =
			{
				"edu.internet2.middleware.shibboleth.hs.provider.CryptoHandleRepository.keyStorePath",
				"edu.internet2.middleware.shibboleth.hs.provider.CryptoHandleRepository.keyStorePassword",
				"edu.internet2.middleware.shibboleth.hs.provider.CryptoHandleRepository.keyStoreKeyAlias",
				"edu.internet2.middleware.shibboleth.hs.provider.CryptoHandleRepository.keyStoreKeyPassword" };

		for (int i = 0; i < requiredProperties.length; i++) {
			if (params.getProperty(requiredProperties[i]) == null) {
				missingProperties.append("\"");
				missingProperties.append(requiredProperties[i]);
				missingProperties.append("\" ");
			}
		}
		if (missingProperties.length() > 0) {
			log.error(
				"Missing configuration data.  The following configuration properites are required for the Crypto Handle Repository and have not been set: "
					+ missingProperties.toString());
			throw new HandleRepositoryException("Missing configuration data.");
		}
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.hs.HandleRepository#getHandle(Principal)
	 */
	public String getHandle(AuthNPrincipal principal, StringBuffer format) throws HandleRepositoryException {
		try {
			if (principal == null || format == null) {
				log.error("A principal and format buffer must be supplied for Attribute Query Handle creation.");
				throw new IllegalArgumentException("A principal and format buffer must be supplied for Attribute Query Handle creation.");
			}

			HandleEntry handleEntry = createHandleEntry(principal);

			Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(secret);
			HMACHandleEntry macHandleEntry = new HMACHandleEntry(handleEntry, mac);

			ByteArrayOutputStream outStream = new ByteArrayOutputStream();
			ByteArrayOutputStream encStream = new ByteArrayOutputStream();

			Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
			byte[] iv = new byte[8];
			random.nextBytes(iv);
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			cipher.init(Cipher.ENCRYPT_MODE, secret, ivSpec);

			//Handle contains 8 byte IV, followed by cipher text
			outStream.write(cipher.getIV());

			ObjectOutput objectStream = new ObjectOutputStream(new GZIPOutputStream(encStream));
			objectStream.writeObject(macHandleEntry);
			objectStream.close();

			outStream.write(cipher.doFinal(encStream.toByteArray()));
			encStream.close();

			String handle = new BASE64Encoder().encode(outStream.toByteArray());
			outStream.close();

			format.setLength(0);
			format.append(Constants.SHIB_NAMEID_FORMAT_URI);

			return handle.replaceAll(System.getProperty("line.separator"), "");

		} catch (KeyException e) {
			log.error("Could not use the supplied secret key: " + e);
			throw new HandleRepositoryException("Could not use the supplied secret key.");
		} catch (GeneralSecurityException e) {
			log.error("Appropriate JCE provider not found in the java environment.  Could not load Cipher: " + e);
			throw new HandleRepositoryException("Appropriate JCE provider not found in the java environment.  Could not load Cipher.");
		} catch (IOException e) {
			log.error("Could not serialize Principal for handle creation: " + e);
			throw new HandleRepositoryException("Could not serialize Principal for Attribute Query Handle creation.");
		}
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.hs.HandleRepository#getPrincipal(String)
	 */
	public AuthNPrincipal getPrincipal(String handle, String format)
		throws HandleRepositoryException, InvalidHandleException {
		if (!Constants.SHIB_NAMEID_FORMAT_URI.equals(format)) {
			log.debug(
				"This Repository does not understand handles with a format URI of "
					+ (format == null ? "null" : format));
			throw new InvalidHandleException(
				"This Repository does not understand handles with a format URI of "
					+ (format == null ? "null" : format));
		}

		try {
			//Separate the IV and handle
			byte[] in = new BASE64Decoder().decodeBuffer(handle);
			if (in.length < 9) {
				log.debug("Attribute Query Handle is malformed (not enough bytes).");
				throw new InvalidHandleException("Attribute Query Handle is malformed (not enough bytes).");
			}
			byte[] iv = new byte[8];
			System.arraycopy(in, 0, iv, 0, 8);
			byte[] encryptedHandle = new byte[in.length - iv.length];
			System.arraycopy(in, 8, encryptedHandle, 0, in.length - iv.length);

			Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			cipher.init(Cipher.DECRYPT_MODE, secret, ivSpec);

			byte[] objectArray = cipher.doFinal(encryptedHandle);
			GZIPInputStream zipBytesIn = new GZIPInputStream(new ByteArrayInputStream(objectArray));

			ObjectInputStream objectStream = new ObjectInputStream(zipBytesIn);

			HMACHandleEntry handleEntry = (HMACHandleEntry) objectStream.readObject();
			objectStream.close();

			if (handleEntry.isExpired()) {
				log.debug("Attribute Query Handle is expired.");
				throw new InvalidHandleException("Attribute Query Handle is expired.");
			}

			Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(secret);
			if (!handleEntry.isValid(mac)) {
				log.warn("Attribute Query Handle failed integrity check.");
				throw new InvalidHandleException("Attribute Query Handle failed integrity check.");
			}

			log.debug("Attribute Query Handle recognized.");
			return handleEntry.principal;

		} catch (NoSuchAlgorithmException e) {
			log.error("Appropriate JCE provider not found in the java environment.  Could not load Algorithm: " + e);
			throw new HandleRepositoryException("Appropriate JCE provider not found in the java environment.  Could not load Algorithm.");
		} catch (NoSuchPaddingException e) {
			log.error(
				"Appropriate JCE provider not found in the java environment.  Could not load Padding method: " + e);
			throw new HandleRepositoryException("Appropriate JCE provider not found in the java environment.  Could not load Padding method.");
		} catch (InvalidKeyException e) {
			log.error("Could not use the supplied secret key: " + e);
			throw new HandleRepositoryException("Could not use the supplied secret key.");
		} catch (GeneralSecurityException e) {
			log.warn("Unable to decrypt the supplied Attribute Query Handle: " + e);
			throw new InvalidHandleException("Unable to decrypt the supplied Attribute Query Handle.");
		} catch (ClassNotFoundException e) {
			log.warn("The supplied Attribute Query Handle does not represent a serialized AuthNPrincipal: " + e);
			throw new InvalidHandleException("The supplied Attribute Query Handle does not represent a serialized AuthNPrincipal.");
		} catch (IOException e) {
			log.warn("The AuthNPrincipal could not be de-serialized from the supplied Attribute Query Handle: " + e);
			throw new InvalidHandleException("The AuthNPrincipal could not be de-serialized from the supplied Attribute Query Handle.");
		}
	}

	private void testEncryption() throws HandleRepositoryException {

		String decrypted;
		try {
			Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secret);
			byte[] cipherText = cipher.doFinal("test".getBytes());
			cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, secret);
			decrypted = new String(cipher.doFinal(cipherText));
		} catch (Exception e) {
			log.error("Round trip encryption/decryption test unsuccessful: " + e);
			throw new HandleRepositoryException("Round trip encryption/decryption test unsuccessful.");
		}

		if (decrypted == null || !decrypted.equals("test")) {
			log.error("Round trip encryption/decryption test unsuccessful.  Decrypted text did not match.");
			throw new HandleRepositoryException("Round trip encryption/decryption test unsuccessful.");
		}

		byte[] code;
		try {
			Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(secret);
			mac.update("foo".getBytes());
			code = mac.doFinal();

		} catch (Exception e) {
			log.error("Message Authentication test unsuccessful: " + e);
			throw new HandleRepositoryException("Message Authentication test unsuccessful.");
		}

		if (code == null) {
			log.error("Message Authentication test unsuccessful.");
			throw new HandleRepositoryException("Message Authentication test unsuccessful.");
		}
	}

}



/**
 * <code>HandleEntry</code> extension class that performs message authentication.
 * 
 */
class HMACHandleEntry extends HandleEntry implements Serializable {

	static final long serialVersionUID = 1L;
	protected byte[] code;

	protected HMACHandleEntry(AuthNPrincipal principal, long TTL, Mac mac) {
		super(principal, TTL);
		mac.update(this.principal.getName().getBytes());
		mac.update(new Long(this.expirationTime).byteValue());
		code = mac.doFinal();
	}

	protected HMACHandleEntry(HandleEntry handleEntry, Mac mac) {
		super(handleEntry.principal, handleEntry.expirationTime);
		mac.update(this.principal.getName().getBytes());
		mac.update(new Long(this.expirationTime).byteValue());
		code = mac.doFinal();
	}

	boolean isValid(Mac mac) {
		mac.update(this.principal.getName().getBytes());
		mac.update(new Long(this.expirationTime).byteValue());
		byte[] validationCode = mac.doFinal();
		return Arrays.equals(code, validationCode);
	}
}
