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
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import sun.misc.BASE64Decoder;

/**
 * @author Walter Hoehn
 *  
 */
public class Credentials {

	public static final String credentialsNamespace = "urn:mace:shibboleth:credentials:1.0";

	private static Logger log = Logger.getLogger(Credentials.class.getName());
	private Hashtable data = new Hashtable();

	public Credentials(Element e) {

		if (!e.getTagName().equals("Credentials")) {
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
			if (e.getTagName().equals("KeyInfo")) {
				return new KeyInfoCredentialResolver().loadCredential(e);
			}

			if (e.getTagName().equals("FileResolver")) {
				return new FileCredentialResolver().loadCredential(e);
			}

			if (e.getTagName().equals("KeyStoreResolver")) {
				return new KeystoreCredentialResolver().loadCredential(e);
			}

			if (e.getTagName().equals("CustomResolver")) {
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

	public Credential loadCredential(Element e) throws CredentialFactoryException {

		if (!e.getTagName().equals("FileResolver")) {
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
		log.debug("Key Format: (" + keyFormat + ").");
		log.debug("Key Path: (" + keyPath + ").");

		String keyAlgorithm = "RSA";

		//TODO providers?
		//TODO support DER, PEM, DER-PKCS8, and PEM-PKCS8?
		//TODO DSA

		PrivateKey key = null;

		if (keyAlgorithm.equals("RSA")) {

			if (keyFormat.equals("DER")) {
				try {
					key = getRSADERKey(new ShibResource(keyPath, this.getClass()).getInputStream());
				} catch (IOException ioe) {
					log.error("Could not load resource from specified location (" + keyPath + "): " + e);
					throw new CredentialFactoryException("Unable to load private key.");
				}
			} else if (keyFormat.equals("PEM")) {
				try {
					key = getRSAPEMKey(new ShibResource(keyPath, this.getClass()).getInputStream());
				} catch (IOException ioe) {
					log.error("Could not load resource from specified location (" + keyPath + "): " + e);
					throw new CredentialFactoryException("Unable to load private key.");
				}
			} else {
				log.error("File credential resolver only supports (DER) and (PEM) formats.");
				throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
			}

		} else {
			log.error("File credential resolver only supports the RSA keys.");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

		String certFormat = getCertFormat(e);
		String certPath = getCertPath(e);
		//A placeholder in case we ever want to make this configurable
		String certType = "X.509";

		log.debug("Certificate Format: (" + certFormat + ").");
		log.debug("Certificate Path: (" + certPath + ").");

		//TODO provider optional
		//TODO provide a way to specify a separate CA bundle

		//The loading code should work for other types, but the chain construction code
		//would break
		if (!certType.equals("X.509")) {
			log.error("File credential resolver only supports the X.509 certificates.");
			throw new CredentialFactoryException("Failed to initialize Credential Resolver.");
		}

		ArrayList certChain = new ArrayList();
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

			//TODO probably don't want to require a full chain
			log.debug("Attempting to construct a certificate chain.");
			walkChain((X509Certificate[]) allCerts.toArray(new X509Certificate[0]), certChain);

			log.info("Verifying that each link in the cert chain is signed appropriately");
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

		} catch (IOException p) {
			log.error("Could not load resource from specified location (" + certPath + "): " + p);
			throw new CredentialFactoryException("Unable to load certificates.");
		}

		return new Credential(((X509Certificate[]) certChain.toArray(new X509Certificate[0])), key);
	}

	private PrivateKey getRSADERKey(InputStream inStream) throws CredentialFactoryException {

		try {

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			byte[] inputBuffer = new byte[8];
			int i;
			ByteContainer inputBytes = new ByteContainer(400);
			do {
				i = inStream.read(inputBuffer);
				for (int j = 0; j < i; j++) {
					inputBytes.append(inputBuffer[j]);
				}
			} while (i > -1);

			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(inputBytes.toByteArray());

			return keyFactory.generatePrivate(keySpec);

		} catch (Exception e) {
			log.error("Unable to load private key: " + e);
			throw new CredentialFactoryException("Unable to load private key.");
		}

	}

	private PrivateKey getRSAPEMKey(InputStream inStream) throws CredentialFactoryException {

		try {

			BufferedReader in = new BufferedReader(new InputStreamReader(inStream));
			String str;
			boolean insideBase64 = false;
			StringBuffer base64Key = null;
			while ((str = in.readLine()) != null) {

				if (insideBase64) {
					if (str.matches("^.*-----END PRIVATE KEY-----.*$")) {
						break;
					}
					{
						base64Key.append(str);
					}
				} else if (str.matches("^.*-----BEGIN PRIVATE KEY-----.*$")) {
					insideBase64 = true;
					base64Key = new StringBuffer();
				}
			}
			in.close();
			if (base64Key == null || base64Key.length() == 0) {
				log.error("Did not find BASE 64 encoded private key in file.");
				throw new CredentialFactoryException("Unable to load private key.");
			}

			BASE64Decoder decoder = new BASE64Decoder();
			//Probably want to give a different error for this exception
			byte[] pkcs8Bytes = decoder.decodeBuffer(base64Key.toString());
			try {
				PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8Bytes);
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				return keyFactory.generatePrivate(keySpec);

			} catch (Exception e) {
				log.error("Unable to load private key: " + e);
				throw new CredentialFactoryException("Unable to load private key.");
			}
		} catch (IOException p) {
			log.error("Could not load resource from specified location: " + p);
			throw new CredentialFactoryException("Unable to load key.");
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
			log.error("Multiple Keyf path specifications, using first.");
		}

		String format = ((Element) keyElements.item(0)).getAttribute("format");
		if (format == null || format.equals("")) {
			log.debug("No format specified for certificate, using default (PEM) format.");
			format = "PEM";
		}
		//TODO smarter
		/*
		 * if (!format.equals("DER-PKCS8")) { log.error("File credential resolver currently only supports (DER-PKCS8)
		 * format."); throw new CredentialFactoryException("Failed to initialize Credential Resolver."); }
		 */
		return format;
	}

	private String getCertPath(Element e) throws CredentialFactoryException {

		NodeList certificateElements = e.getElementsByTagNameNS(Credentials.credentialsNamespace, "Certificate");
		if (certificateElements.getLength() < 1) {
			log.error("Certificate not specified.");
			throw new CredentialFactoryException("File Credential Resolver requires a <Certificate> specification.");
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
			//TODO maybe this should check more than the DN...
			for (int i = 0; chainSource.length > i; i++) {
				if (currentCert.getIssuerDN().equals(chainSource[i].getSubjectDN())) {
					chainDest.add(chainSource[i]);
					walkChain(chainSource, chainDest);
					return;
				}
			}
			log.error("Incomplete certificate chain.");
			throw new CredentialFactoryException("Incomplete cerficate chain.");
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

		if (!e.getTagName().equals("KeyStoreResolver")) {
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

		if (!e.getTagName().equals("CustomCredResolver")) {
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
