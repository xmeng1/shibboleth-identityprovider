/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved
 * 
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 * disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided with the distribution, if any, must include the
 * following acknowledgment: "This product includes software developed by the University Corporation for Advanced
 * Internet Development <http://www.ucaid.edu> Internet2 Project. Alternately, this acknowledegement may appear in the
 * software itself, if and wherever such third-party acknowledgments normally appear.
 * 
 * Neither the name of Shibboleth nor the names of its contributors, nor Internet2, nor the University Corporation for
 * Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote products derived from this software
 * without specific prior written permission. For written permission, please contact shibboleth@shibboleth.org
 * 
 * Products derived from this software may not be called Shibboleth, Internet2, UCAID, or the University Corporation
 * for Advanced Internet Development, nor may Shibboleth appear in their name, without prior written permission of the
 * University Corporation for Advanced Internet Development.
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE,
 * ACCURACY, AND EFFORT IS WITH LICENSEE. IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.common;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import sun.misc.BASE64Decoder;
import sun.security.util.DerValue;

/**
 * @author Walter Hoehn
 *  
 */
public class Credentials {

	public static final String credentialsNamespace = "urn:mace:shibboleth:credentials:1.0";

	private static Logger log = Logger.getLogger(Credentials.class.getName());
	private Hashtable data = new Hashtable();

	public Credentials(Element e) {

		if (!e.getLocalName().equals("Credentials")) {
			throw new IllegalArgumentException();
		}

		NodeList resolverNodes = e.getChildNodes();
		if (resolverNodes.getLength() <= 0) {
			log.error("Credentials configuration inclues no Credential Resolver definitions.");
			throw new IllegalArgumentException("Cannot load credentials.");
		}

		for (int i = 0; resolverNodes.getLength() > i; i++) {
			if (resolverNodes.item(i).getNodeType() == Node.ELEMENT_NODE) {
				try {

					String credentialId = ((Element) resolverNodes.item(i)).getAttribute("Id");
					if (credentialId == null || credentialId.equals("")) {
						log.error("Found credential that was not labeled with a unique \"Id\" attribute. Skipping.");
					}

					if (data.containsKey(credentialId)) {
						log.error("Duplicate credential id (" + credentialId + ") found. Skipping");
					}

					log.info("Found credential (" + credentialId + "). Loading...");
					data.put(credentialId, CredentialFactory.loadCredential((Element) resolverNodes.item(i)));

				} catch (CredentialFactoryException cfe) {
					log.error("Could not load credential, skipping: " + cfe.getMessage());
				} catch (ClassCastException cce) {
					log.error("Problem realizing credential configuration" + cce.getMessage());
				}
			}
		}
	}

	public boolean containsCredential(String identifier) {
		return data.containsKey(identifier);
	}

	public Credential getCredential(String identifier) {
		return (Credential) data.get(identifier);
	}

	static class CredentialFactory {

		private static Logger log = Logger.getLogger(CredentialFactory.class.getName());

		public static Credential loadCredential(Element e) throws CredentialFactoryException {
			if (e.getLocalName().equals("KeyInfo")) {
				return new KeyInfoCredentialResolver().loadCredential(e);
			}

			if (e.getLocalName().equals("FileResolver")) {
				return new FileCredentialResolver().loadCredential(e);
			}

			if (e.getLocalName().equals("KeyStoreResolver")) {
				return new KeystoreCredentialResolver().loadCredential(e);
			}

			if (e.getLocalName().equals("CustomResolver")) {
				return new CustomCredentialResolver().loadCredential(e);
			}

			log.error("Unrecognized Credential Resolver type: " + e.getTagName());
			throw new CredentialFactoryException("Failed to load credential.");
		}

	}

}

class KeyInfoCredentialResolver implements CredentialResolver {
	private static Logger log = Logger.getLogger(KeyInfoCredentialResolver.class.getName());
	KeyInfoCredentialResolver() throws CredentialFactoryException {
		log.error("Credential Resolver (KeyInfoCredentialResolver) not implemented");
		throw new CredentialFactoryException("Failed to load credential.");
	}

	public Credential loadCredential(Element e) {
		return null;
	}
}

class FileCredentialResolver implements CredentialResolver {

	private static Logger log = Logger.getLogger(FileCredentialResolver.class.getName());

	private static String DSAKey_OID = "1.2.840.10040.4.1";
	private static String RSAKey_OID = "1.2.840.113549.1.1.1";

	public Credential loadCredential(Element e) throws CredentialFactoryException {

		if (!e.getLocalName().equals("FileResolver")) {
			log.error("Invalid Credential Resolver configuration: expected <FileResolver> .");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

		String id = e.getAttribute("Id");
		if (id == null || id.equals("")) {
			log.error("Credential Resolvers require specification of the attribute \"Id\".");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

		//Load the key
		String keyFormat = getKeyFormat(e);
		String keyPath = getKeyPath(e);
		String password = getKeyPassword(e);
		log.debug("Key Format: (" + keyFormat + ").");
		log.debug("Key Path: (" + keyPath + ").");

		PrivateKey key = null;

		if (keyFormat.equals("DER")) {
			try {
				key = getDERKey(new ShibResource(keyPath, this.getClass()).getInputStream(), password);
			} catch (IOException ioe) {
				log.error("Could not load resource from specified location (" + keyPath + "): " + e);
				throw new CredentialFactoryException("Unable to load private key.");
			}
		} else if (keyFormat.equals("PEM")) {
			try {
				key = getPEMKey(new ShibResource(keyPath, this.getClass()).getInputStream(), password);
			} catch (IOException ioe) {
				log.error("Could not load resource from specified location (" + keyPath + "): " + e);
				throw new CredentialFactoryException("Unable to load private key.");
			}
		} else {
			log.error("File credential resolver only supports (DER) and (PEM) formats.");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

		if (key == null) {
			log.error("Failed to load private key.");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}
		log.info("Successfully loaded private key.");

		
		ArrayList certChain = new ArrayList();
		String certPath = getCertPath(e);
		
		if (certPath == null || certPath.equals("")) {
			log.info("No certificates specified.");
		} else {

		String certFormat = getCertFormat(e);
		//A placeholder in case we want to make this configurable
		String certType = "X.509";

		log.debug("Certificate Format: (" + certFormat + ").");
		log.debug("Certificate Path: (" + certPath + ").");

		//The loading code should work for other types, but the chain
		// construction code
		//would break
		if (!certType.equals("X.509")) {
			log.error("File credential resolver only supports the X.509 certificates.");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}


		ArrayList allCerts = new ArrayList();

		try {
			Certificate[] certsFromPath =
				loadCertificates(new ShibResource(certPath, this.getClass()).getInputStream(), certType);

			allCerts.addAll(Arrays.asList(certsFromPath));

			//Find the end-entity cert first
			if (certsFromPath == null || certsFromPath.length == 0) {
				log.error("File at (" + certPath + ") did not contain any valid certificates.");
				throw new CredentialFactoryException("File did not contain any valid certificates.");
			}

			if (certsFromPath.length == 1) {
				log.debug("Certificate file only contains 1 certificate.");
				log.debug("Ensure that it matches the private key.");
				if (!isMatchingKey(certsFromPath[0].getPublicKey(), key)) {
					log.error("Certificate does not match the private key.");
					throw new CredentialFactoryException("File did not contain any valid certificates.");
				}
				certChain.add(certsFromPath[0]);
				log.debug(
					"Successfully identified the end entity cert: "
						+ ((X509Certificate) certChain.get(0)).getSubjectDN());

			} else {
				log.debug("Certificate file contains multiple certificates.");
				log.debug("Trying to determine the end-entity cert by matching against the private key.");
				for (int i = 0; certsFromPath.length > i; i++) {
					if (isMatchingKey(certsFromPath[i].getPublicKey(), key)) {
						log.debug("Found matching end cert: " + ((X509Certificate) certsFromPath[i]).getSubjectDN());
						certChain.add(certsFromPath[i]);
					}
				}
				if (certChain.size() < 1) {
					log.error("No certificate in chain that matches specified private key");
					throw new CredentialFactoryException("No certificate in chain that matches specified private key");
				}
				if (certChain.size() > 1) {
					log.error("More than one certificate in chain that matches specified private key");
					throw new CredentialFactoryException("More than one certificate in chain that matches specified private key");
				}
				log.debug(
					"Successfully identified the end entity cert: "
						+ ((X509Certificate) certChain.get(0)).getSubjectDN());
			}

			//Now load additional certs and construct a chain
			String[] caPaths = getCAPaths(e);
			if (caPaths != null && caPaths.length > 0) {
				log.debug("Attempting to load certificates from (" + caPaths.length + ") CA certificate files.");
				for (int i = 0; i < caPaths.length; i++) {
					allCerts.addAll(
						Arrays.asList(
							loadCertificates(
								new ShibResource(caPaths[i], this.getClass()).getInputStream(),
								certType)));
				}
			}

			log.debug("Attempting to construct a certificate chain.");
			walkChain((X509Certificate[]) allCerts.toArray(new X509Certificate[0]), certChain);

			log.debug("Verifying that each link in the cert chain is signed appropriately");
			for (int i = 0; i < certChain.size() - 1; i++) {
				PublicKey pubKey = ((X509Certificate) certChain.get(i + 1)).getPublicKey();
				try {
					((X509Certificate) certChain.get(i)).verify(pubKey);
				} catch (Exception se) {
					log.error("Certificate chain cannot be verified: " + se);
					throw new CredentialFactoryException("Certificate chain cannot be verified: " + se);
				}
			}
			log.debug("All signatures verified. Certificate chain creation successful.");
			log.info("Successfully loaded certificates.");
		

		} catch (IOException p) {
			log.error("Could not load resource from specified location (" + certPath + "): " + p);
			throw new CredentialFactoryException("Unable to load certificates.");
		}
		}
		return new Credential(((X509Certificate[]) certChain.toArray(new X509Certificate[0])), key);
	}

	private PrivateKey getDERKey(InputStream inStream, String password)
		throws CredentialFactoryException, IOException {

		byte[] inputBuffer = new byte[8];
		int i;
		ByteContainer inputBytes = new ByteContainer(800);
		do {
			i = inStream.read(inputBuffer);
			for (int j = 0; j < i; j++) {
				inputBytes.append(inputBuffer[j]);
			}
		} while (i > -1);

		//Examine the ASN.1 Structure to auto-detect the format
		//This gets a tad nasty
		try {
			DerValue root = new DerValue(inputBytes.toByteArray());
			if (root.tag != DerValue.tag_Sequence) {
				log.error("Unexpected data type.  Unable to determine key type from data.");
				throw new CredentialFactoryException("Unable to load private key.");
			}

			DerValue[] childValues = new DerValue[3];

			if (root.data.available() == 0) {
				log.error("Unexpected data type.  Unable to determine key type from data.");
				throw new CredentialFactoryException("Unable to load private key.");
			}

			childValues[0] = root.data.getDerValue();

			if (childValues[0].tag == DerValue.tag_Sequence) {

				//May be encrypted pkcs8... dig further
				if (root.data.available() == 0) {
					log.error("Unexpected data type.  Unable to determine key type from data.");
					throw new CredentialFactoryException("Unable to load private key.");
				}
				childValues[1] = root.data.getDerValue();
				if (childValues[1].tag != DerValue.tag_OctetString) {
					log.error("Unexpected data type.  Unable to determine key type from data.");
					throw new CredentialFactoryException("Unable to load private key.");
				}

				if (childValues[0].data.available() == 0) {
					log.error("Unexpected data type.  Unable to determine key type from data.");
					throw new CredentialFactoryException("Unable to load private key.");
				}
				DerValue grandChild = childValues[0].data.getDerValue();
				if (grandChild.tag != DerValue.tag_ObjectId) {
					log.error("Unexpected data type.  Unable to determine key type from data.");
					throw new CredentialFactoryException("Unable to load private key.");
				}

				log.debug("Key appears to be formatted as encrypted PKCS8. Loading...");
				return getEncryptedPkcs8Key(inputBytes.toByteArray(), password.toCharArray());

			} else if (childValues[0].tag == DerValue.tag_Integer) {

				//May be pkcs8, rsa, or dsa... dig further
				if (root.data.available() == 0) {
					log.error("Unexpected data type.  Unable to determine key type from data.");
					throw new CredentialFactoryException("Unable to load private key.");
				}
				childValues[1] = root.data.getDerValue();
				if (childValues[1].tag == DerValue.tag_Sequence) {
					//May be pkcs8... dig further
					if (root.data.available() == 0) {
						log.error("Unexpected data type.  Unable to determine key type from data.");
						throw new CredentialFactoryException("Unable to load private key.");
					}
					childValues[2] = root.data.getDerValue();
					if (childValues[2].tag != DerValue.tag_OctetString) {
						log.error("Unexpected data type.  Unable to determine key type from data.");
						throw new CredentialFactoryException("Unable to load private key.");
					}

					if (childValues[1].data.available() == 0) {
						log.error("Unexpected data type.  Unable to determine key type from data.");
						throw new CredentialFactoryException("Unable to load private key.");
					}
					DerValue grandChild = childValues[1].data.getDerValue();
					if (grandChild.tag != DerValue.tag_ObjectId) {
						log.error("Unexpected data type.  Unable to determine key type from data.");
						throw new CredentialFactoryException("Unable to load private key.");
					}

					log.debug("Key appears to be formatted as PKCS8. Loading...");
					return getRSAPkcs8DerKey(inputBytes.toByteArray());

				} else if (childValues[1].tag == DerValue.tag_Integer) {

					//May be rsa or dsa... dig further
					if (root.data.available() == 0
						|| root.data.getDerValue().tag != DerValue.tag_Integer
						|| root.data.available() == 0
						|| root.data.getDerValue().tag != DerValue.tag_Integer
						|| root.data.available() == 0
						|| root.data.getDerValue().tag != DerValue.tag_Integer
						|| root.data.available() == 0
						|| root.data.getDerValue().tag != DerValue.tag_Integer) {
						log.error("Unexpected data type.  Unable to determine key type from data.");
						throw new CredentialFactoryException("Unable to load private key.");
					}

					if (root.data.available() == 0) {

						log.debug("Key appears to be DSA. Loading...");
						return getDSARawDerKey(inputBytes.toByteArray());

					} else {

						DerValue dsaOverrun = root.data.getDerValue();
						if (dsaOverrun.tag != DerValue.tag_Integer) {
							log.error("Unexpected data type.  Unable to determine key type from data.");
							throw new CredentialFactoryException("Unable to load private key.");
						}

						log.debug("Key appears to be RSA. Loading...");
						return getRSARawDerKey(inputBytes.toByteArray());
					}

				} else {
					log.error("Unexpected data type.  Unable to determine key type from data.");
					throw new CredentialFactoryException("Unable to load private key.");
				}

			} else {
				log.error("Unexpected data type.  Unable to determine key type from data.");
				throw new CredentialFactoryException("Unable to load private key.");
			}

		} catch (CredentialFactoryException e) {
			log.error("Invalid DER encoding for key: " + e);
			throw new CredentialFactoryException("Unable to load private key.");
		}

	}

	private PrivateKey getPEMKey(InputStream inStream, String password)
		throws CredentialFactoryException, IOException {

		byte[] inputBuffer = new byte[8];
		int i;
		ByteContainer inputBytes = new ByteContainer(800);
		do {
			i = inStream.read(inputBuffer);
			for (int j = 0; j < i; j++) {
				inputBytes.append(inputBuffer[j]);
			}
		} while (i > -1);

		BufferedReader in =
			new BufferedReader(new InputStreamReader(new ByteArrayInputStream(inputBytes.toByteArray())));
		String str;
		while ((str = in.readLine()) != null) {

			if (str.matches("^.*-----BEGIN PRIVATE KEY-----.*$")) {
				log.debug("Key appears to be in PKCS8 format.");
				in.close();
				return getPkcs8Key(
					singleDerFromPEM(
						inputBytes.toByteArray(),
						"-----BEGIN PRIVATE KEY-----",
						"-----END PRIVATE KEY-----"));

			} else if (str.matches("^.*-----BEGIN RSA PRIVATE KEY-----.*$")) {
				String nextStr = in.readLine();
				if (nextStr != null && nextStr.matches("^.*Proc-Type: 4,ENCRYPTED.*$")) {
					log.debug("Key appears to be encrypted RSA in raw format.");
					return getRawEncryptedPemKey(inputBytes.toByteArray(), password);
				}

				in.close();
				log.debug("Key appears to be RSA in raw format.");
				return getRSARawDerKey(
					singleDerFromPEM(
						inputBytes.toByteArray(),
						"-----BEGIN RSA PRIVATE KEY-----",
						"-----END RSA PRIVATE KEY-----"));

			} else if (str.matches("^.*-----BEGIN DSA PRIVATE KEY-----.*$")) {
				String nextStr = in.readLine();
				if (nextStr != null && nextStr.matches("^.*Proc-Type: 4,ENCRYPTED.*$")) {
					log.debug("Key appears to be encrypted DSA in raw format.");
					return getRawEncryptedPemKey(inputBytes.toByteArray(), password);
				}
				in.close();
				log.debug("Key appears to be DSA in raw format.");
				return getDSARawDerKey(
					singleDerFromPEM(
						inputBytes.toByteArray(),
						"-----BEGIN DSA PRIVATE KEY-----",
						"-----END DSA PRIVATE KEY-----"));

			} else if (str.matches("^.*-----BEGIN ENCRYPTED PRIVATE KEY-----.*$")) {
				in.close();
				log.debug("Key appears to be in encrypted PKCS8 format.");
				return getEncryptedPkcs8Key(
					singleDerFromPEM(
						inputBytes.toByteArray(),
						"-----BEGIN ENCRYPTED PRIVATE KEY-----",
						"-----END ENCRYPTED PRIVATE KEY-----"),
					password.toCharArray());
			}
		}
		in.close();
		log.error("Unsupported formatting.  Available PEM types are PKCS8, Raw RSA, and Raw DSA.");
		throw new CredentialFactoryException("Failed to initialize Credential Resolver.");

	}

	private PrivateKey getRSAPkcs8DerKey(byte[] bytes) throws CredentialFactoryException {

		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
			return keyFactory.generatePrivate(keySpec);

		} catch (Exception e) {
			log.error("Unable to load private key: " + e);
			throw new CredentialFactoryException("Unable to load private key.");
		}
	}

	private PrivateKey getDSAPkcs8DerKey(byte[] bytes) throws CredentialFactoryException {

		try {
			KeyFactory keyFactory = KeyFactory.getInstance("DSA");
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
			return keyFactory.generatePrivate(keySpec);

		} catch (Exception e) {
			log.error("Unable to load private key: " + e);
			throw new CredentialFactoryException("Unable to load private key.");
		}
	}

	private PrivateKey getRSARawDerKey(byte[] bytes) throws CredentialFactoryException {

		try {
			DerValue root = new DerValue(bytes);
			if (root.tag != DerValue.tag_Sequence) {
				log.error("Unexpected data type.  Unable to load data as an RSA key.");
				throw new CredentialFactoryException("Unable to load private key.");
			}

			DerValue[] childValues = new DerValue[10];
			childValues[0] = root.data.getDerValue();
			childValues[1] = root.data.getDerValue();
			childValues[2] = root.data.getDerValue();
			childValues[3] = root.data.getDerValue();
			childValues[4] = root.data.getDerValue();
			childValues[5] = root.data.getDerValue();
			childValues[6] = root.data.getDerValue();
			childValues[7] = root.data.getDerValue();
			childValues[8] = root.data.getDerValue();

			//This data is optional.
			if (root.data.available() != 0) {
				childValues[9] = root.data.getDerValue();
				if (root.data.available() != 0) {
					log.error("Data overflow.  Unable to load data as an RSA key.");
					throw new CredentialFactoryException("Unable to load private key.");
				}
			}

			if (childValues[0].tag != DerValue.tag_Integer
				|| childValues[1].tag != DerValue.tag_Integer
				|| childValues[2].tag != DerValue.tag_Integer
				|| childValues[3].tag != DerValue.tag_Integer
				|| childValues[4].tag != DerValue.tag_Integer
				|| childValues[5].tag != DerValue.tag_Integer
				|| childValues[6].tag != DerValue.tag_Integer
				|| childValues[7].tag != DerValue.tag_Integer
				|| childValues[8].tag != DerValue.tag_Integer) {
				log.error("Unexpected data type.  Unable to load data as an RSA key.");
				throw new CredentialFactoryException("Unable to load private key.");
			}

			RSAPrivateCrtKeySpec keySpec =
				new RSAPrivateCrtKeySpec(
					childValues[1].getBigInteger(),
					childValues[2].getBigInteger(),
					childValues[3].getBigInteger(),
					childValues[4].getBigInteger(),
					childValues[5].getBigInteger(),
					childValues[6].getBigInteger(),
					childValues[7].getBigInteger(),
					childValues[8].getBigInteger());

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");

			return keyFactory.generatePrivate(keySpec);

		} catch (IOException e) {
			log.error("Invalid DER encoding for RSA key: " + e);
			throw new CredentialFactoryException("Unable to load private key.");
		} catch (GeneralSecurityException e) {
			log.error("Unable to marshall private key: " + e);
			throw new CredentialFactoryException("Unable to load private key.");
		}

	}
	private PrivateKey getRawEncryptedPemKey(byte[] bytes, String password) throws CredentialFactoryException {

		try {
			String algorithm = null;
			String algParams = null;

			BufferedReader in = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(bytes)));
			String str;
			boolean insideBase64 = false;
			StringBuffer base64Key = null;
			while ((str = in.readLine()) != null) {

				if (insideBase64) {
					if (str.matches("^.*Proc-Type: 4,ENCRYPTED.*$")) {
						continue;
					}

					if (str.matches("^.*DEK-Info:.*$")) {
						String[] components = str.split(":\\s");
						if (components.length != 2) {
							log.error("Encrypted key did not contain DEK-Info specification.");
							throw new CredentialFactoryException("Unable to load private key.");
						}
						String[] cryptData = components[1].split(",");
						if (cryptData.length != 2
							|| cryptData[0] == null
							|| cryptData[0].equals("")
							|| cryptData[1] == null
							|| cryptData[1].equals("")) {
							log.error("Encrypted key did not contain a proper DEK-Info specification.");
							throw new CredentialFactoryException("Unable to load private key.");
						}
						algorithm = cryptData[0];
						algParams = cryptData[1];
						continue;
					}
					if (str.equals("")) {
						continue;
					}

					if (str.matches("^.*-----END [DR]SA PRIVATE KEY-----.*$")) {
						break;
					}
					{
						base64Key.append(str);
					}
				} else if (str.matches("^.*-----BEGIN [DR]SA PRIVATE KEY-----.*$")) {
					insideBase64 = true;
					base64Key = new StringBuffer();
				}
			}
			in.close();
			if (base64Key == null || base64Key.length() == 0) {
				log.error("Could not find Base 64 encoded entity.");
				throw new IOException("Could not find Base 64 encoded entity.");
			}

			BASE64Decoder decoder = new BASE64Decoder();
			byte[] encryptedBytes = decoder.decodeBuffer(base64Key.toString());

			byte[] ivBytes = new byte[8];
			for (int j = 0; j < 8; j++) {
				ivBytes[j] = (byte) Integer.parseInt(algParams.substring(j * 2, j * 2 + 2), 16);
			}
			IvParameterSpec paramSpec = new IvParameterSpec(ivBytes);

			if ((!algorithm.equals("DES-CBC")) && (!algorithm.equals("DES-EDE3-CBC"))) {
				log.error(
					"Connot decrypt key with algorithm ("
						+ algorithm
						+ ").  Supported algorithms for raw (OpenSSL) keys are (DES-CBC) and (DES-EDE3-CBC).");
				throw new CredentialFactoryException("Unable to load private key.");
			}

			byte[] keyBuffer = new byte[24];
			//The key generation method (with the IV used as the salt, and
			//the single proprietary iteration)
			//is the reason we can't use the pkcs5 providers to read the
			// OpenSSL encrypted format

			MessageDigest md = MessageDigest.getInstance("MD5");
			md.update(password.getBytes());
			md.update(paramSpec.getIV());
			byte[] digested = md.digest();
			System.arraycopy(digested, 0, keyBuffer, 0, 16);

			md.update(digested);
			md.update(password.getBytes());
			md.update(paramSpec.getIV());
			digested = md.digest();
			System.arraycopy(digested, 0, keyBuffer, 16, 8);

			SecretKeySpec keySpec = null;
			Cipher cipher = null;
			if (algorithm.equals("DES-CBC")) {
				//Special handling!!!
				//For DES, we use the same key generation,
				//then just chop off the end :-)
				byte[] desBuff = new byte[8];
				System.arraycopy(keyBuffer, 0, desBuff, 0, 8);
				keySpec = new SecretKeySpec(desBuff, "DES");
				cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
			}
			if (algorithm.equals("DES-EDE3-CBC")) {
				keySpec = new SecretKeySpec(keyBuffer, "DESede");
				cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
			}

			cipher.init(Cipher.DECRYPT_MODE, keySpec, paramSpec);
			byte[] decrypted = cipher.doFinal(encryptedBytes);

			return getDERKey(new ByteArrayInputStream(decrypted), password);

		} catch (IOException ioe) {
			log.error("Could not decode Base 64: " + ioe);
			throw new CredentialFactoryException("Unable to load private key.");

		} catch (BadPaddingException e) {
			log.debug(e.getMessage());
			log.error("Incorrect password to unlock private key.");
			throw new CredentialFactoryException("Unable to load private key.");
		} catch (Exception e) {
			log.error(
				"Unable to decrypt private key.  Installed JCE implementations don't support the necessary algorithm: "
					+ e);
			throw new CredentialFactoryException("Unable to load private key.");
		}
	}

	private PrivateKey getDSARawDerKey(byte[] bytes) throws CredentialFactoryException {

		try {
			DerValue root = new DerValue(bytes);
			if (root.tag != DerValue.tag_Sequence) {
				log.error("Unexpected data type.  Unable to load data as an DSA key.");
				throw new CredentialFactoryException("Unable to load private key.");
			}

			DerValue[] childValues = new DerValue[6];
			childValues[0] = root.data.getDerValue();
			childValues[1] = root.data.getDerValue();
			childValues[2] = root.data.getDerValue();
			childValues[3] = root.data.getDerValue();
			childValues[4] = root.data.getDerValue();
			childValues[5] = root.data.getDerValue();

			if (root.data.available() != 0) {
				log.error("Data overflow.  Unable to load data as an DSA key.");
				throw new CredentialFactoryException("Unable to load private key.");
			}

			if (childValues[0].tag != DerValue.tag_Integer
				|| childValues[1].tag != DerValue.tag_Integer
				|| childValues[2].tag != DerValue.tag_Integer
				|| childValues[3].tag != DerValue.tag_Integer
				|| childValues[4].tag != DerValue.tag_Integer
				|| childValues[5].tag != DerValue.tag_Integer) {
				log.error("Unexpected data type.  Unable to load data as an DSA key.");
				throw new CredentialFactoryException("Unable to load private key.");
			}

			DSAPrivateKeySpec keySpec =
				new DSAPrivateKeySpec(
					childValues[5].getBigInteger(),
					childValues[1].getBigInteger(),
					childValues[2].getBigInteger(),
					childValues[3].getBigInteger());

			KeyFactory keyFactory = KeyFactory.getInstance("DSA");

			return keyFactory.generatePrivate(keySpec);

		} catch (IOException e) {
			log.error("Invalid DER encoding for DSA key: " + e);
			throw new CredentialFactoryException("Unable to load private key.");
		} catch (GeneralSecurityException e) {
			log.error("Unable to marshall private key: " + e);
			throw new CredentialFactoryException("Unable to load private key.");
		}

	}

	private PrivateKey getPkcs8Key(byte[] bytes) throws CredentialFactoryException {

		try {
			DerValue root = new DerValue(bytes);
			if (root.tag != DerValue.tag_Sequence) {
				log.error("Unexpected data type.  Unable to load data as a PKCS8 formatted key.");
				throw new CredentialFactoryException("Unable to load private key.");
			}

			DerValue[] childValues = new DerValue[2];
			childValues[0] = root.data.getDerValue();
			childValues[1] = root.data.getDerValue();

			if (childValues[0].tag != DerValue.tag_Integer || childValues[1].tag != DerValue.tag_Sequence) {
				log.error("Unexpected data type.  Unable to load data as a PKCS8 formatted key.");
				throw new CredentialFactoryException("Unable to load private key.");
			}

			DerValue grandChild = childValues[1].data.getDerValue();
			if (grandChild.tag != DerValue.tag_ObjectId) {
				log.error("Unexpected data type.  Unable to load data as a PKCS8 formatted key.");
				throw new CredentialFactoryException("Unable to load private key.");
			}

			String keyOID = grandChild.getOID().toString();
			if (keyOID.equals(FileCredentialResolver.RSAKey_OID)) {
				log.debug("Found RSA key in PKCS8.");
				return getRSAPkcs8DerKey(bytes);
			} else if (keyOID.equals(FileCredentialResolver.DSAKey_OID)) {
				log.debug("Found DSA key in PKCS8.");
				return getDSAPkcs8DerKey(bytes);
			} else {
				log.error("Unexpected key type.  Only RSA and DSA keys are supported in PKCS8 format.");
				throw new CredentialFactoryException("Unable to load private key.");
			}

		} catch (IOException e) {
			log.error("Invalid DER encoding for PKCS8 formatted key: " + e);
			throw new CredentialFactoryException("Unable to load private key.");
		}
	}

	private PrivateKey getEncryptedPkcs8Key(byte[] bytes, char[] password) throws CredentialFactoryException {

		try {

			//Convince the JCE provider that it does know how to do
			// pbeWithMD5AndDES-CBC
			Provider provider = Security.getProvider("SunJCE");
			if (provider != null) {
				provider.setProperty("Alg.Alias.AlgorithmParameters.1.2.840.113549.1.5.3", "PBE");
				provider.setProperty("Alg.Alias.SecretKeyFactory.1.2.840.113549.1.5.3", "PBEWithMD5AndDES");
				provider.setProperty("Alg.Alias.Cipher.1.2.840.113549.1.5.3", "PBEWithMD5AndDES");
			}

			EncryptedPrivateKeyInfo encryptedKeyInfo = new EncryptedPrivateKeyInfo(bytes);
			AlgorithmParameters params = encryptedKeyInfo.getAlgParameters();

			if (params == null) {
				log.error(
					"Unable to decrypt private key.  Installed JCE implementations don't support the ("
						+ encryptedKeyInfo.getAlgName()
						+ ") algorithm.");
				throw new CredentialFactoryException("Unable to load private key.");
			}

			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(encryptedKeyInfo.getAlgName());
			PBEKeySpec passwordSpec = new PBEKeySpec(password);
			SecretKey key = keyFactory.generateSecret(passwordSpec);

			Cipher cipher = Cipher.getInstance(encryptedKeyInfo.getAlgName());
			cipher.init(Cipher.DECRYPT_MODE, key, params);
			PKCS8EncodedKeySpec decrypted = encryptedKeyInfo.getKeySpec(cipher);

			return getPkcs8Key(decrypted.getEncoded());

		} catch (IOException e) {
			e.printStackTrace();
			log.error("Invalid DER encoding for PKCS8 formatted encrypted key: " + e);
			throw new CredentialFactoryException("Unable to load private key.");
		} catch (InvalidKeySpecException e) {
			log.debug(e.getMessage());
			log.error("Incorrect password to unlock private key.");
			throw new CredentialFactoryException("Unable to load private key.");
		} catch (Exception e) {
			log.error(
				"Unable to decrypt private key.  Installed JCE implementations don't support the necessary algorithm: "
					+ e);
			throw new CredentialFactoryException("Unable to load private key.");
		}

	}

	private byte[] singleDerFromPEM(byte[] bytes, String beginToken, String endToken) throws IOException {

		try {

			BufferedReader in = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(bytes)));
			String str;
			boolean insideBase64 = false;
			StringBuffer base64Key = null;
			while ((str = in.readLine()) != null) {

				if (insideBase64) {
					if (str.matches("^.*" + endToken + ".*$")) {
						break;
					}
					{
						base64Key.append(str);
					}
				} else if (str.matches("^.*" + beginToken + ".*$")) {
					insideBase64 = true;
					base64Key = new StringBuffer();
				}
			}
			in.close();
			if (base64Key == null || base64Key.length() == 0) {
				log.error("Could not find Base 64 encoded entity.");
				throw new IOException("Could not find Base 64 encoded entity.");
			}

			try {
				BASE64Decoder decoder = new BASE64Decoder();
				return decoder.decodeBuffer(base64Key.toString());
			} catch (IOException ioe) {
				log.error("Could not decode Base 64: " + ioe);
				throw new IOException("Could not decode Base 64.");
			}

		} catch (IOException e) {
			log.error("Could not load resource from specified location: " + e);
			throw new IOException("Could not load resource from specified location.");
		}

	}

	private String getCertFormat(Element e) throws CredentialFactoryException {

		NodeList certificateElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "Certificate");
		if (certificateElements.getLength() < 1) {
			log.error("Certificate not specified.");
			throw new CredentialFactoryException("File Credential Resolver requires a <Certificate> specification.");
		}
		if (certificateElements.getLength() > 1) {
			log.error("Multiple Certificate path specifications, using first.");
		}

		String format = ((Element) certificateElements.item(0)).getAttribute("format");
		if (format == null || format.equals("")) {
			log.debug("No format specified for certificate, using default (PEM) format.");
			format = "PEM";
		}

		if ((!format.equals("PEM")) && (!format.equals("DER"))) {
			log.error("File credential resolver only supports the (DER) and (PEM) formats.");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

		return format;
	}

	private String getKeyFormat(Element e) throws CredentialFactoryException {

		NodeList keyElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "Key");
		if (keyElements.getLength() < 1) {
			log.error("Key not specified.");
			throw new CredentialFactoryException("File Credential Resolver requires a <Key> specification.");
		}
		if (keyElements.getLength() > 1) {
			log.error("Multiple Key path specifications, using first.");
		}

		String format = ((Element) keyElements.item(0)).getAttribute("format");
		if (format == null || format.equals("")) {
			log.debug("No format specified for certificate, using default (PEM) format.");
			format = "PEM";
		}

		if (!((format.equals("DER")) || (format.equals("PEM")))) {
			log.error("File credential resolver currently only supports (DER) and (PEM) formats.");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}
		return format;
	}

	private String getKeyPassword(Element e) throws CredentialFactoryException {

		NodeList keyElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "Key");
		if (keyElements.getLength() < 1) {
			log.error("Key not specified.");
			throw new CredentialFactoryException("File Credential Resolver requires a <Key> specification.");
		}

		if (keyElements.getLength() > 1) {
			log.error("Multiple Key path specifications, using first.");
		}

		String password = ((Element) keyElements.item(0)).getAttribute("password");
		if (password == null) {
			password = "";
		}
		return password;
	}

	private String getCertPath(Element e) throws CredentialFactoryException {

		NodeList certificateElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "Certificate");
		if (certificateElements.getLength() < 1) {
			log.debug("No <Certificate> element found.");
			return null;
		}
		if (certificateElements.getLength() > 1) {
			log.error("Multiple Certificate path specifications, using first.");
		}

		NodeList pathElements =
			((Element) certificateElements.item(0)).getElementsByTagNameNS(Credentials.credentialsNamespace, "Path");
		if (pathElements.getLength() < 1) {
			log.error("Certificate path not specified.");
			throw new CredentialFactoryException("File Credential Resolver requires a <Certificate><Path/></Certificate> specification.");
		}
		if (pathElements.getLength() > 1) {
			log.error("Multiple Certificate path specifications, using first.");
		}
		Node tnode = pathElements.item(0).getFirstChild();
		String path = null;
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			path = tnode.getNodeValue();
		}
		if (path == null || path.equals("")) {
			log.error("Certificate path not specified.");
			throw new CredentialFactoryException("File Credential Resolver requires a <Certificate><Path/></Certificate> specification.");
		}
		return path;
	}

	private String[] getCAPaths(Element e) throws CredentialFactoryException {

		NodeList certificateElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "Certificate");
		if (certificateElements.getLength() < 1) {
			log.error("Certificate not specified.");
			throw new CredentialFactoryException("File Credential Resolver requires a <Certificate> specification.");
		}
		if (certificateElements.getLength() > 1) {
			log.error("Multiple Certificate path specifications, using first.");
		}

		NodeList pathElements =
			((Element) certificateElements.item(0)).getElementsByTagNameNS(Credentials.credentialsNamespace, "CAPath");
		if (pathElements.getLength() < 1) {
			log.debug("No CA Certificate paths specified.");
			return null;
		}
		ArrayList paths = new ArrayList();
		for (int i = 0; i < pathElements.getLength(); i++) {
			Node tnode = pathElements.item(i).getFirstChild();
			String path = null;
			if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
				path = tnode.getNodeValue();
			}
			if (path != null && !(path.equals(""))) {
				paths.add(path);
			}
			if (paths.isEmpty()) {
				log.debug("No CA Certificate paths specified.");
			}
		}
		return (String[]) paths.toArray(new String[0]);
	}

	private String getKeyPath(Element e) throws CredentialFactoryException {

		NodeList keyElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "Key");
		if (keyElements.getLength() < 1) {
			log.error("Key not specified.");
			throw new CredentialFactoryException("File Credential Resolver requires a <Key> specification.");
		}
		if (keyElements.getLength() > 1) {
			log.error("Multiple Key path specifications, using first.");
		}

		NodeList pathElements =
			((Element) keyElements.item(0)).getElementsByTagNameNS(Credentials.credentialsNamespace, "Path");
		if (pathElements.getLength() < 1) {
			log.error("Key path not specified.");
			throw new CredentialFactoryException("File Credential Resolver requires a <Key><Path/></Certificate> specification.");
		}
		if (pathElements.getLength() > 1) {
			log.error("Multiple Key path specifications, using first.");
		}
		Node tnode = pathElements.item(0).getFirstChild();
		String path = null;
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			path = tnode.getNodeValue();
		}
		if (path == null || path.equals("")) {
			log.error("Key path not specified.");
			throw new CredentialFactoryException("File Credential Resolver requires a <Key><Path/></Certificate> specification.");
		}
		return path;
	}

	/**
	 * 
	 * Loads a specified bundle of certs individually and returns an array of <code>Certificate</code> objects. This
	 * is needed because the standard <code>CertificateFactory.getCertificates(InputStream)</code> method bails out
	 * when it has trouble loading any cert and cannot handle "comments".
	 */
	private Certificate[] loadCertificates(InputStream inStream, String certType) throws CredentialFactoryException {

		ArrayList certificates = new ArrayList();

		try {
			CertificateFactory certFactory = CertificateFactory.getInstance(certType);

			BufferedReader in = new BufferedReader(new InputStreamReader(inStream));
			String str;
			boolean insideCert = false;
			StringBuffer rawCert = null;
			while ((str = in.readLine()) != null) {

				if (insideCert) {
					rawCert.append(str);
					rawCert.append(System.getProperty("line.separator"));
					if (str.matches("^.*-----END CERTIFICATE-----.*$")) {
						insideCert = false;
						try {
							Certificate cert =
								certFactory.generateCertificate(
									new ByteArrayInputStream(rawCert.toString().getBytes()));
							certificates.add(cert);
						} catch (CertificateException ce) {
							log.warn("Failed to load a certificate from the certificate bundle: " + ce);
							if (log.isDebugEnabled()) {
								log.debug(
									"Dump of bad certificate: "
										+ System.getProperty("line.separator")
										+ rawCert.toString());
							}
						}
						continue;
					}
				} else if (str.matches("^.*-----BEGIN CERTIFICATE-----.*$")) {
					insideCert = true;
					rawCert = new StringBuffer();
					rawCert.append(str);
					rawCert.append(System.getProperty("line.separator"));
				}
			}
			in.close();
		} catch (IOException p) {
			log.error("Could not load resource from specified location: " + p);
			throw new CredentialFactoryException("Unable to load certificates.");
		} catch (CertificateException p) {
			log.error("Problem loading certificate factory: " + p);
			throw new CredentialFactoryException("Unable to load certificates.");
		}

		return (Certificate[]) certificates.toArray(new Certificate[0]);
	}

	/**
	 * Given an ArrayList containing a base certificate and an array of unordered certificates, populates the ArrayList
	 * with an ordered certificate chain, based on subject and issuer.
	 * 
	 * @param chainSource
	 *            array of certificates to pull from
	 * @param chainDest
	 *            ArrayList containing base certificate
	 * @throws InvalidCertificateChainException
	 *             thrown if a chain cannot be constructed from the specified elements
	 */

	protected void walkChain(X509Certificate[] chainSource, ArrayList chainDest) throws CredentialFactoryException {

		X509Certificate currentCert = (X509Certificate) chainDest.get(chainDest.size() - 1);
		if (currentCert.getSubjectDN().equals(currentCert.getIssuerDN())) {
			log.debug("Found self-signed root cert: " + currentCert.getSubjectDN());
			return;
		} else {
			for (int i = 0; chainSource.length > i; i++) {
				if (currentCert.getIssuerDN().equals(chainSource[i].getSubjectDN())) {
					chainDest.add(chainSource[i]);
					walkChain(chainSource, chainDest);
					return;
				}
			}
			log.debug("Certificate chain is incomplete.");
		}
	}

	/**
	 * Boolean indication of whether a given private key and public key form a valid keypair.
	 * 
	 * @param pubKey
	 *            the public key
	 * @param privKey
	 *            the private key
	 */

	protected boolean isMatchingKey(PublicKey pubKey, PrivateKey privKey) {

		try {
			String controlString = "asdf";
			log.debug("Checking for matching private key/public key pair");
			Signature signature = null;
			try {
				signature = Signature.getInstance(privKey.getAlgorithm());
			} catch (NoSuchAlgorithmException nsae) {
				log.debug("No provider for (RSA) signature, attempting (MD5withRSA).");
				if (privKey.getAlgorithm().equals("RSA")) {
					signature = Signature.getInstance("MD5withRSA");
				} else {
					throw nsae;
				}
			}
			signature.initSign(privKey);
			signature.update(controlString.getBytes());
			byte[] sigBytes = signature.sign();
			signature.initVerify(pubKey);
			signature.update(controlString.getBytes());
			if (signature.verify(sigBytes)) {
				log.debug("Found match.");
				return true;
			}
		} catch (Exception e) {
			log.warn(e);
		}
		log.debug("This pair does not match.");
		return false;
	}

	/**
	 * Auto-enlarging container for bytes.
	 */

	// Sure makes you wish bytes were first class objects.

	private class ByteContainer {

		private byte[] buffer;
		private int cushion;
		private int currentSize = 0;

		private ByteContainer(int cushion) {
			buffer = new byte[cushion];
			this.cushion = cushion;
		}

		private void grow() {
			log.debug("Growing ByteContainer.");
			int newSize = currentSize + cushion;
			byte[] b = new byte[newSize];
			int toCopy = Math.min(currentSize, newSize);
			int i;
			for (i = 0; i < toCopy; i++) {
				b[i] = buffer[i];
			}
			buffer = b;
		}

		/**
		 * Returns an array of the bytes in the container.
		 * <p>
		 */

		private byte[] toByteArray() {
			byte[] b = new byte[currentSize];
			for (int i = 0; i < currentSize; i++) {
				b[i] = buffer[i];
			}
			return b;
		}

		/**
		 * Add one byte to the end of the container.
		 */

		private void append(byte b) {
			if (currentSize == buffer.length) {
				grow();
			}
			buffer[currentSize] = b;
			currentSize++;
		}

	}

}

class KeystoreCredentialResolver implements CredentialResolver {

	private static Logger log = Logger.getLogger(KeystoreCredentialResolver.class.getName());

	public Credential loadCredential(Element e) throws CredentialFactoryException {

		if (!e.getLocalName().equals("KeyStoreResolver")) {
			log.error("Invalid Credential Resolver configuration: expected <KeyStoreResolver> .");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

		String id = e.getAttribute("Id");
		if (id == null || id.equals("")) {
			log.error("Credential Resolvers require specification of the attribute \"Id\".");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

		String keyStoreType = e.getAttribute("storeType");
		if (keyStoreType == null || keyStoreType.equals("")) {
			log.debug("Using default store type for credential.");
			keyStoreType = "JKS";
		}

		String path = loadPath(e);
		String alias = loadAlias(e);
		String certAlias = loadCertAlias(e, alias);
		String keyPassword = loadKeyPassword(e);
		String keyStorePassword = loadKeyStorePassword(e);

		try {
			KeyStore keyStore = KeyStore.getInstance(keyStoreType);

			keyStore.load(new ShibResource(path, this.getClass()).getInputStream(), keyStorePassword.toCharArray());

			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyPassword.toCharArray());

			if (privateKey == null) {
				throw new CredentialFactoryException("No key entry was found with an alias of (" + alias + ").");
			}

			Certificate[] certificates = keyStore.getCertificateChain(certAlias);
			if (certificates == null) {
				throw new CredentialFactoryException(
					"An error occurred while reading the java keystore: No certificate found with the specified alias ("
						+ certAlias
						+ ").");
			}

			X509Certificate[] x509Certs = new X509Certificate[certificates.length];
			for (int i = 0; i < certificates.length; i++) {
				if (certificates[i] instanceof X509Certificate) {
					x509Certs[i] = (X509Certificate) certificates[i];
				} else {
					throw new CredentialFactoryException(
						"The KeyStore Credential Resolver can only load X509 certificates.  Found an unsupported certificate of type ("
							+ certificates[i]
							+ ").");
				}
			}

			return new Credential(x509Certs, privateKey);

		} catch (KeyStoreException kse) {
			throw new CredentialFactoryException("An error occurred while accessing the java keystore: " + kse);
		} catch (NoSuchAlgorithmException nsae) {
			throw new CredentialFactoryException("Appropriate JCE provider not found in the java environment: " + nsae);
		} catch (CertificateException ce) {
			throw new CredentialFactoryException(
				"The java keystore contained a certificate that could not be loaded: " + ce);
		} catch (IOException ioe) {
			throw new CredentialFactoryException("An error occurred while reading the java keystore: " + ioe);
		} catch (UnrecoverableKeyException uke) {
			throw new CredentialFactoryException(
				"An error occurred while attempting to load the key from the java keystore: " + uke);
		}

	}

	private String loadPath(Element e) throws CredentialFactoryException {

		NodeList pathElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "Path");
		if (pathElements.getLength() < 1) {
			log.error("KeyStore path not specified.");
			throw new CredentialFactoryException("KeyStore Credential Resolver requires a <Path> specification.");
		}
		if (pathElements.getLength() > 1) {
			log.error("Multiple KeyStore path specifications, using first.");
		}
		Node tnode = pathElements.item(0).getFirstChild();
		String path = null;
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			path = tnode.getNodeValue();
		}
		if (path == null || path.equals("")) {
			log.error("KeyStore path not specified.");
			throw new CredentialFactoryException("KeyStore Credential Resolver requires a <Path> specification.");
		}
		return path;
	}

	private String loadAlias(Element e) throws CredentialFactoryException {

		NodeList aliasElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "KeyAlias");
		if (aliasElements.getLength() < 1) {
			log.error("KeyStore key alias not specified.");
			throw new CredentialFactoryException("KeyStore Credential Resolver requires an <KeyAlias> specification.");
		}
		if (aliasElements.getLength() > 1) {
			log.error("Multiple key alias specifications, using first.");
		}
		Node tnode = aliasElements.item(0).getFirstChild();
		String alias = null;
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			alias = tnode.getNodeValue();
		}
		if (alias == null || alias.equals("")) {
			log.error("KeyStore key alias not specified.");
			throw new CredentialFactoryException("KeyStore Credential Resolver requires an <KeyAlias> specification.");
		}
		return alias;
	}

	private String loadCertAlias(Element e, String defaultAlias) throws CredentialFactoryException {

		NodeList aliasElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "CertAlias");
		if (aliasElements.getLength() < 1) {
			log.debug("KeyStore cert alias not specified, defaulting to key alias.");
			return defaultAlias;
		}

		if (aliasElements.getLength() > 1) {
			log.error("Multiple cert alias specifications, using first.");
		}

		Node tnode = aliasElements.item(0).getFirstChild();
		String alias = null;
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			alias = tnode.getNodeValue();
		}
		if (alias == null || alias.equals("")) {
			log.debug("KeyStore cert alias not specified, defaulting to key alias.");
			return defaultAlias;
		}
		return alias;
	}

	private String loadKeyStorePassword(Element e) throws CredentialFactoryException {

		NodeList passwordElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "StorePassword");
		if (passwordElements.getLength() < 1) {
			log.error("KeyStore password not specified.");
			throw new CredentialFactoryException("KeyStore Credential Resolver requires an <StorePassword> specification.");
		}
		if (passwordElements.getLength() > 1) {
			log.error("Multiple KeyStore password specifications, using first.");
		}
		Node tnode = passwordElements.item(0).getFirstChild();
		String password = null;
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			password = tnode.getNodeValue();
		}
		if (password == null || password.equals("")) {
			log.error("KeyStore password not specified.");
			throw new CredentialFactoryException("KeyStore Credential Resolver requires an <StorePassword> specification.");
		}
		return password;
	}

	private String loadKeyPassword(Element e) throws CredentialFactoryException {

		NodeList passwords = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "KeyPassword");
		if (passwords.getLength() < 1) {
			log.error("KeyStore key password not specified.");
			throw new CredentialFactoryException("KeyStore Credential Resolver requires an <KeyPassword> specification.");
		}
		if (passwords.getLength() > 1) {
			log.error("Multiple KeyStore key password specifications, using first.");
		}
		Node tnode = passwords.item(0).getFirstChild();
		String password = null;
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			password = tnode.getNodeValue();
		}
		if (password == null || password.equals("")) {
			log.error("KeyStore key password not specified.");
			throw new CredentialFactoryException("KeyStore Credential Resolver requires an <KeyPassword> specification.");
		}
		return password;
	}
}

class CustomCredentialResolver implements CredentialResolver {

	private static Logger log = Logger.getLogger(CustomCredentialResolver.class.getName());

	public Credential loadCredential(Element e) throws CredentialFactoryException {

		if (!e.getLocalName().equals("CustomCredResolver")) {
			log.error("Invalid Credential Resolver configuration: expected <CustomCredResolver> .");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

		String id = e.getAttribute("id");
		if (id == null || id.equals("")) {
			log.error("Credential Resolvers require specification of the attribute \"id\".");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

		String className = e.getAttribute("Class");
		if (className == null || className.equals("")) {
			log.error("Custom Credential Resolver requires specification of the attribute \"Class\".");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

		try {
			return ((CredentialResolver) Class.forName(className).newInstance()).loadCredential(e);

		} catch (Exception loaderException) {
			log.error(
				"Failed to load Custom Credential Resolver implementation class: " + loaderException.getMessage());
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

	}

}

class CredentialFactoryException extends Exception {

	CredentialFactoryException(String message) {
		super(message);
	}
}
