/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation
 * for Advanced Internet Development, Inc. All rights reserved
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
 * <http://www.ucaid.edu> Internet2 Project. Alternately, this acknowledegement
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
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.hs.provider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.io.StreamCorruptedException;
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
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.log4j.Logger;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;
import edu.internet2.middleware.shibboleth.common.IdentityProvider;
import edu.internet2.middleware.shibboleth.common.InvalidNameIdentifierException;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMapping;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMappingException;
import edu.internet2.middleware.shibboleth.common.ServiceProvider;
import edu.internet2.middleware.shibboleth.common.ShibResource;
import edu.internet2.middleware.shibboleth.hs.HSNameIdentifierMapping;

/**
 * <code>HSNameIdentifierMapping</code> implementation that uses symmetric
 * encryption to securely transport principal data inside Shibboleth Attribute
 * Query Handles.
 * 
 * @author Walter Hoehn
 */
public class CryptoShibHandle extends AQHNameIdentifierMapping implements HSNameIdentifierMapping {

	private static Logger log = Logger.getLogger(CryptoShibHandle.class.getName());
	protected SecretKey secret;
	private SecureRandom random = new SecureRandom();

	public CryptoShibHandle(Element config) throws NameIdentifierMappingException {
		super(config);
		try {

			String keyStorePath = getElementConfigData(config, "KeyStorePath");
			String keyStorePassword = getElementConfigData(config, "KeyStorePassword");
			String keyStoreKeyAlias = getElementConfigData(config, "KeyStoreKeyAlias");
			String keyStoreKeyPassword = getElementConfigData(config, "KeyStoreKeyPassword");

			KeyStore keyStore = KeyStore.getInstance("JCEKS");
			keyStore.load(
				new ShibResource(keyStorePath, this.getClass()).getInputStream(),
				keyStorePassword.toCharArray());
			secret = (SecretKey) keyStore.getKey(keyStoreKeyAlias, keyStoreKeyPassword.toCharArray());

			//Before we finish initilization, make sure that things are
			// working
			testEncryption();

			if (usingDefaultSecret()) {
				log.warn(
					"You are running Crypto AQH Name Mapping with the default secret key.  This is UNSAFE!  Please change "
						+ "this configuration and restart the origin.");
			}
		} catch (StreamCorruptedException e) {
			if (System.getProperty("java.version").startsWith("1.4.2")) {
				log.error(
					"There is a bug in Java 1.4.2 that prevents JCEKS keystores from being loaded properly.  "
						+ "You probably need to upgrade or downgrade your JVM in order to make this work.");
			}
			log.error(
				"An error occurred while loading the java keystore.  Unable to initialize Crypto Name Mapping: " + e);
			throw new NameIdentifierMappingException("An error occurred while loading the java keystore.  Unable to initialize Crypto Name Mapping.");
		} catch (KeyStoreException e) {
			log.error(
				"An error occurred while loading the java keystore.  Unable to initialize Crypto Name Mapping: " + e);
			throw new NameIdentifierMappingException("An error occurred while loading the java keystore.  Unable to initialize Crypto Name Mapping.");
		} catch (CertificateException e) {
			log.error("The java keystore contained corrupted data.  Unable to initialize Crypto Name Mapping: " + e);
			throw new NameIdentifierMappingException("The java keystore contained corrupted data.  Unable to initialize Crypto Name Mapping.");
		} catch (NoSuchAlgorithmException e) {
			log.error(
				"Appropriate JCE provider not found in the java environment. Unable to initialize Crypto Name Mapping: "
					+ e);
			throw new NameIdentifierMappingException("Appropriate JCE provider not found in the java environment. Unable to initialize Crypto Name Mapping.");
		} catch (IOException e) {
			log.error(
				"An error accessing while loading the java keystore.  Unable to initialize Crypto Name Mapping: " + e);
			throw new NameIdentifierMappingException("An error occurred while accessing the java keystore.  Unable to initialize Crypto Name Mapping.");
		} catch (UnrecoverableKeyException e) {
			log.error(
				"Secret could not be loaded from the java keystore.  Verify that the alias and password are correct: "
					+ e);
			throw new NameIdentifierMappingException("Secret could not be loaded from the java keystore.  Verify that the alias and password are correct. ");
		}
	}

	public AuthNPrincipal getPrincipal(SAMLNameIdentifier nameId, ServiceProvider sProv, IdentityProvider idProv)
		throws NameIdentifierMappingException, InvalidNameIdentifierException {

		try {
			//Separate the IV and handle
			byte[] in = new BASE64Decoder().decodeBuffer(nameId.getName());
			if (in.length < 9) {
				log.debug("Attribute Query Handle is malformed (not enough bytes).");
				throw new InvalidNameIdentifierException("Attribute Query Handle is malformed (not enough bytes).");
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
				throw new InvalidNameIdentifierException("Attribute Query Handle is expired.");
			}

			Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(secret);
			if (!handleEntry.isValid(mac)) {
				log.warn("Attribute Query Handle failed integrity check.");
				throw new InvalidNameIdentifierException("Attribute Query Handle failed integrity check.");
			}

			log.debug("Attribute Query Handle recognized.");
			return handleEntry.principal;

		} catch (NoSuchAlgorithmException e) {
			log.error("Appropriate JCE provider not found in the java environment.  Could not load Algorithm: " + e);
			throw new InvalidNameIdentifierException("Appropriate JCE provider not found in the java environment.  Could not load Algorithm.");
		} catch (NoSuchPaddingException e) {
			log.error(
				"Appropriate JCE provider not found in the java environment.  Could not load Padding method: " + e);
			throw new InvalidNameIdentifierException("Appropriate JCE provider not found in the java environment.  Could not load Padding method.");
		} catch (InvalidKeyException e) {
			log.error("Could not use the supplied secret key: " + e);
			throw new InvalidNameIdentifierException("Could not use the supplied secret key.");
		} catch (GeneralSecurityException e) {
			log.warn("Unable to decrypt the supplied Attribute Query Handle: " + e);
			throw new InvalidNameIdentifierException("Unable to decrypt the supplied Attribute Query Handle.");
		} catch (ClassNotFoundException e) {
			log.warn("The supplied Attribute Query Handle does not represent a serialized AuthNPrincipal: " + e);
			throw new InvalidNameIdentifierException("The supplied Attribute Query Handle does not represent a serialized AuthNPrincipal.");
		} catch (IOException e) {
			log.warn("The AuthNPrincipal could not be de-serialized from the supplied Attribute Query Handle: " + e);
			throw new InvalidNameIdentifierException("The AuthNPrincipal could not be de-serialized from the supplied Attribute Query Handle.");
		}
	}

	public SAMLNameIdentifier getNameIdentifierName(
		AuthNPrincipal principal,
		ServiceProvider sProv,
		IdentityProvider idProv)
		throws NameIdentifierMappingException {
		try {
			if (principal == null) {
				log.error("A principal must be supplied for Attribute Query Handle creation.");
				throw new IllegalArgumentException("A principal must be supplied for Attribute Query Handle creation.");
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

			try {
				return new SAMLNameIdentifier(
					handle.replaceAll(System.getProperty("line.separator"), ""),
					idProv.getId(),
					getNameIdentifierFormat().toString());
			} catch (SAMLException e) {
				throw new NameIdentifierMappingException("Unable to generate Attribute Query Handle: " + e);
			}

		} catch (KeyException e) {
			log.error("Could not use the supplied secret key: " + e);
			throw new NameIdentifierMappingException("Could not use the supplied secret key.");
		} catch (GeneralSecurityException e) {
			log.error("Appropriate JCE provider not found in the java environment.  Could not load Cipher: " + e);
			throw new NameIdentifierMappingException("Appropriate JCE provider not found in the java environment.  Could not load Cipher.");
		} catch (IOException e) {
			log.error("Could not serialize Principal for handle creation: " + e);
			throw new NameIdentifierMappingException("Could not serialize Principal for Attribute Query Handle creation.");
		}
	}

	private String getElementConfigData(Element e, String itemName) throws NameIdentifierMappingException {

		NodeList itemElements =e.getElementsByTagNameNS(NameIdentifierMapping.mappingNamespace, itemName);
		
		if (itemElements.getLength() < 1) {
			log.error(itemName + " not specified.");
			throw new NameIdentifierMappingException(
				"Crypto Name Mapping requires a <" + itemName + "> specification.");
		}

		if (itemElements.getLength() > 1) {
			log.error("Multiple " + itemName + " specifications, using first.");
		}

		Node tnode = itemElements.item(0).getFirstChild();
		String item = null;
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			item = tnode.getNodeValue();
		}
		if (item == null || item.equals("")) {
			log.error(itemName + " not specified.");
			throw new NameIdentifierMappingException(
				"Crypto Name Mapping requires a <" + itemName + "> specification.");
		}
		return item;
	}

	private void testEncryption() throws NameIdentifierMappingException {

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
			throw new NameIdentifierMappingException("Round trip encryption/decryption test unsuccessful.");
		}

		if (decrypted == null || !decrypted.equals("test")) {
			log.error("Round trip encryption/decryption test unsuccessful.  Decrypted text did not match.");
			throw new NameIdentifierMappingException("Round trip encryption/decryption test unsuccessful.");
		}

		byte[] code;
		try {
			Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(secret);
			mac.update("foo".getBytes());
			code = mac.doFinal();

		} catch (Exception e) {
			log.error("Message Authentication test unsuccessful: " + e);
			throw new NameIdentifierMappingException("Message Authentication test unsuccessful.");
		}

		if (code == null) {
			log.error("Message Authentication test unsuccessful.");
			throw new NameIdentifierMappingException("Message Authentication test unsuccessful.");
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

}

/**
 * <code>HandleEntry</code> extension class that performs message
 * authentication.
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
