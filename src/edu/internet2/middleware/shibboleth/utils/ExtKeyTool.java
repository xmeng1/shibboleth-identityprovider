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

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Properties;

import javax.crypto.Cipher;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import sun.misc.BASE64Encoder;

/**
 * Extension utility for use alongside Sun's keytool program.  Performs useful functions not found
 * in original.
 * 
 * @author Walter Hoehn
 */

public class ExtKeyTool {

	protected static Logger log = Logger.getLogger(ExtKeyTool.class.getName());

	/** 
	 * Creates and initializes a java <code>KeyStore</code>
	 * 
	 * @param provider			name of the jce provider to use in loading the keystore
	 * @param keyStoreStream	stream used to retrieve the keystore
	 * @param storeType		the type of the keystore
	 * @param keyStorePassword	password used to verify the integrity of the keystore
	 * 
	 * @throws ExtKeyToolException if a problem is encountered loading the keystore
	 */

	protected KeyStore loadKeyStore(
		String provider,
		InputStream keyStoreStream,
		String storeType,
		char[] keyStorePassword)
		throws ExtKeyToolException {

		try {
			if (storeType == null) {
				storeType = "JKS";
			}

			log.debug("Using keystore type: (" + storeType + ")");
			log.debug("Using provider: (" + provider + ")");

			KeyStore keyStore;
			if (storeType.equals("JKS")) {
				keyStore = KeyStore.getInstance(storeType, "SUN");
			} else {
				keyStore = KeyStore.getInstance(storeType, provider);
			}

			if (keyStoreStream == null) {
				log.error("Keystore must be specified.");
				throw new ExtKeyToolException("Keystore must be specified.");
			}
			if (keyStorePassword == null) {
				log.warn("No password given for keystore, integrity will not be verified.");
			}
			keyStore.load(keyStoreStream, keyStorePassword);

			return keyStore;

		} catch (KeyStoreException e) {
			log.error("Problem loading keystore: " + e);
			throw new ExtKeyToolException("Problem loading keystore: " + e);
		} catch (NoSuchProviderException e) {
			log.error("The specified provider is not available.");
			throw new ExtKeyToolException("The specified provider is not available.");
		} catch (CertificateException ce) {
			log.error("Could not open keystore: " + ce);
			throw new ExtKeyToolException("Could not open keystore: " + ce);
		} catch (IOException ioe) {
			log.error("Could not export key: " + ioe);
			throw new ExtKeyToolException("Could not export key: " + ioe);
		} catch (NoSuchAlgorithmException nse) {
			log.error("Could not open keystore with the installed JCE providers: " + nse);
			throw new ExtKeyToolException("Could not open keystore with the installed JCE providers: " + nse);
		}
	}

	/** 
	 * Retrieves a private key from a java keystore and writes it to an <code>PrintStream</code>
	 * 
	 * @param provider			name of the jce provider to use in retrieving the key
	 * @param outStream		stream that should be used to output the retrieved key
	 * @param keyStoreStream	stream used to retrieve the keystore
	 * @param storeType		the type of the keystore
	 * @param keyStorePassword	password used to verify the integrity of the keystore
	 * @param keyAlias			the alias under which the key is stored
	 * @param keyPassword		the password for recovering the key
	 * @param rfc boolean		indicator of whether the key should be Base64 encoded 
	 * 							before being written to the stream
	 * @throws ExtKeyToolException if there a problem retrieving or writing the key
	 */

	public void exportKey(
		String provider,
		PrintStream outStream,
		InputStream keyStoreStream,
		String storeType,
		char[] keyStorePassword,
		String keyAlias,
		char[] keyPassword,
		boolean rfc)
		throws ExtKeyToolException {

		try {

			KeyStore keyStore = loadKeyStore(provider, keyStoreStream, storeType, keyStorePassword);

			if (keyAlias == null) {
				log.error("Key alias must be specified.");
				throw new ExtKeyToolException("Key alias must be specified.");
			}
			log.info("Searching for key.");

			Key key = keyStore.getKey(keyAlias, keyPassword);
			if (key == null) {
				log.error("Key not found in store.");
				throw new ExtKeyToolException("Key not found in store.");
			}
			log.info("Found key.");

			if (rfc) {
				log.debug("Dumping with rfc encoding");
				outStream.println("-----BEGIN PRIVATE KEY-----");
				BASE64Encoder encoder = new BASE64Encoder();
				encoder.encodeBuffer(key.getEncoded(), outStream);
				outStream.println("-----END PRIVATE KEY-----");
			} else {
				log.debug("Dumping with default encoding.");
				outStream.write(key.getEncoded());
			}

		} catch (KeyStoreException e) {
			log.error("Problem accessing keystore: " + e);
			throw new ExtKeyToolException("Problem loading keystore: " + e);
		} catch (IOException ioe) {
			log.error("Could not export key: " + ioe);
			throw new ExtKeyToolException("Could not export key: " + ioe);
		} catch (NoSuchAlgorithmException nse) {
			log.error("Could not recover key with the installed JCE providers: " + nse);
			throw new ExtKeyToolException("Could not recover key with the installed JCE providers: " + nse);
		} catch (UnrecoverableKeyException uke) {
			log.error("The key specified key cannot be recovered with the given password: " + uke);
			throw new ExtKeyToolException(
				"The key specified key cannot be recovered with the given password: " + uke);
		}
	}

	/**
	 * Boolean indication of whether a given private key and public key form a valid keypair.
	 * 
	 * @param pubKey the public key
	 * @param privKey the private key
	 */

	protected boolean isMatchingKey(String algorithm, PublicKey pubKey, PrivateKey privKey) {

		try {
			String controlString = "asdf";
			log.debug("Checking for matching private key/public key pair");
			Cipher cipher = Cipher.getInstance(algorithm);
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			byte[] encryptedData = cipher.doFinal(controlString.getBytes("UTF-8"));

			cipher.init(Cipher.DECRYPT_MODE, privKey);
			byte[] decryptedData = cipher.doFinal(encryptedData);
			if (controlString.equals(new String(decryptedData, "UTF-8"))) {
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
	 * Attempts to unmarshall a private key from a given stream.
	 * 
	 * @param keyStream the <code>InputStream</code> suppying the key
	 * @param algorithm the key algorithm
	 * @throws ExtKeyToolException if there a problem unmarshalling the key
	 */

	protected PrivateKey readPrivateKey(String provider, InputStream keyStream, String algorithm)
		throws ExtKeyToolException {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance(algorithm, provider);

			byte[] inputBuffer = new byte[8];
			int i;
			ByteContainer inputBytes = new ByteContainer(400);
			do {
				i = keyStream.read(inputBuffer);
				for (int j = 0; j < i; j++) {
					inputBytes.append(inputBuffer[j]);
				}
			} while (i > -1);

			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(inputBytes.toByteArray());
			return keyFactory.generatePrivate(keySpec);

		} catch (Exception e) {
			log.error("Problem reading private key: " + e.getMessage());
			throw new ExtKeyToolException("Problem reading private key.  Keys should be DER encoded pkcs8 or DER encoded native format.");
		}
	}

	/**
	 * Converts an array of certificates into an ordered chain.  A
	 * certificate that matches the specified private key will be returned
	 * first and the root certificate will be returned last.
	 * 
	 * @param	untestedCerts array of certificates
	 * @param	privKey the private key used to determine the first cert in the chain
	 * @throws InvalidCertificateChainException thrown if a chain cannot be constructed 
	 * 			from the specified elements
	 */

	protected X509Certificate[] linkChain(
		String keyAlgorithm,
		X509Certificate[] untestedCerts,
		PrivateKey privKey)
		throws InvalidCertificateChainException {

		log.debug("Located " + untestedCerts.length + " cert(s) in input file");

		log.info("Finding end cert in chain.");
		ArrayList replyCerts = new ArrayList();
		for (int i = 0; untestedCerts.length > i; i++) {
			if (isMatchingKey(keyAlgorithm, untestedCerts[i].getPublicKey(), privKey)) {
				log.debug("Found matching end cert: " + untestedCerts[i].getSubjectDN());
				replyCerts.add(untestedCerts[i]);
			}
		}
		if (replyCerts.size() < 1) {
			log.error("No certificate in chain that matches specified private key");
			throw new InvalidCertificateChainException("No certificate in chain that matches specified private key");
		}
		if (replyCerts.size() > 1) {
			log.error("More than one certificate in chain that matches specified private key");
			throw new InvalidCertificateChainException("More than one certificate in chain that matches specified private key");
		}

		log.info("Populating chain with remaining certs.");
		walkChain(untestedCerts, replyCerts);

		log.info("Verifying that each link in the cert chain is signed appropriately");
		for (int i = 0; i < replyCerts.size() - 1; i++) {
			PublicKey pubKey = ((X509Certificate) replyCerts.get(i + 1)).getPublicKey();
			try {
				((X509Certificate) replyCerts.get(i)).verify(pubKey);
			} catch (Exception e) {
				log.error("Certificate chain cannot be verified: " + e.getMessage());
				throw new InvalidCertificateChainException(
					"Certificate chain cannot be verified: " + e.getMessage());
			}
		}
		log.info("All signatures verified. Certificate chain successfully created.");

		return (X509Certificate[]) replyCerts.toArray(new X509Certificate[0]);
	}

	/**
	 * Given an ArrayList containing a base certificate and an array of unordered certificates, 
	 * populates the ArrayList with an ordered certificate chain, based on subject and issuer.
	 * 
	 * @param	chainSource array of certificates to pull from
	 * @param	chainDest ArrayList containing base certificate
	 * @throws InvalidCertificateChainException thrown if a chain cannot be constructed from 
	 * 			the specified elements
	 */

	protected void walkChain(X509Certificate[] chainSource, ArrayList chainDest)
		throws InvalidCertificateChainException {

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
			log.error("Incomplete certificate chain.");
			throw new InvalidCertificateChainException("Incomplete cerficate chain.");
		}
	}

	/** 
	 * Given a java keystore, private key, and matching certificate chain; creates a new 
	 * keystore containing the union of these objects
	 * 
	 * @param provider			the name of the jce provider to use
	 * @param keyAlgorithm		the algorithm of the key to be added, defaults to RSA if null
	 * @param keyStream		strema used to retrieve the private key, can contain a PEM encoded 
	 * 							or pkcs8 encoded key
	 * @param chainStream		stream used to retrieve certificates, can contain a series of 
	 * 							PEM encoded certs or a pkcs7 chain
	 * @param keyStoreInStream	stream used to retrieve the initial keystore
	 * @param storeType		the type of the keystore
	 * @param keyAlias			the alias under which the key/chain should be saved
	 * @param keyStorePassword	password used to verify the integrity of the old keystore and 
	 * 							save the new keystore
	 * @param keyPassword		the password for saving the key
	 * 
	 * @return an OutputStream containing the new keystore
	 * 
	 * @throws ExtKeyToolException if there a problem importing the key
	 */

	public ByteArrayOutputStream importKey(
		String provider,
		String keyAlgorithm,
		InputStream keyStream,
		InputStream chainStream,
		InputStream keyStoreInStream,
		String storeType,
		String keyAlias,
		char[] keyStorePassword,
		char[] keyPassword)
		throws ExtKeyToolException {

		log.info("Importing key pair.");
		try {

			// The Sun provider incorrectly reads only the first cert in the stream.
			// No loss, it won't even read RSA keys
			if (provider == "SUN") {
				log.error("Sorry, this function not supported with the SUN provider.");
				throw new ExtKeyToolException("Sorry, this function not supported with the SUN provider.");
			}

			KeyStore keyStore = loadKeyStore(provider, keyStoreInStream, storeType, keyStorePassword);

			if (keyAlias == null) {
				log.error("Key alias must be specified.");
				throw new ExtKeyToolException("Key alias must be specified.");
			}
			if (keyStore.containsAlias(keyAlias) == true && keyStore.isKeyEntry(keyAlias)) {
				log.error("Could not import key: " + "key alias (" + keyAlias + ") already exists");
				throw new ExtKeyToolException(
					"Could not import key: " + "key alias (" + keyAlias + ") already exists");
			}
			keyStore.deleteEntry(keyAlias);

			log.info("Reading private key.");
			if (keyAlgorithm == null) {
				keyAlgorithm = "RSA";
			}
			log.debug("Using key algorithm: (" + keyAlgorithm + ")");
			PrivateKey key = readPrivateKey(provider, keyStream, keyAlgorithm);

			log.info("Reading certificate chain.");

			CertificateFactory certFactory = CertificateFactory.getInstance("X.509", provider);
			Collection chain = certFactory.generateCertificates(new BufferedInputStream(chainStream));
			if (chain.isEmpty()) {
				log.error("Input did not contain any valid certificates.");
				throw new ExtKeyToolException("Input did not contain any valid certificates.");
			}

			X509Certificate[] verifiedChain =
				linkChain(keyAlgorithm, (X509Certificate[]) chain.toArray(new X509Certificate[0]), key);

			keyStore.setKeyEntry(keyAlias, key, keyPassword, verifiedChain);
			ByteArrayOutputStream keyStoreOutStream = new ByteArrayOutputStream();
			keyStore.store(keyStoreOutStream, keyStorePassword);
			log.info("Key Store saved to stream.");
			return keyStoreOutStream;

		} catch (KeyStoreException e) {
			log.error("Encountered a problem accessing the keystore: " + e.getMessage());
			throw new ExtKeyToolException("Encountered a problem accessing the keystore: " + e.getMessage());
		} catch (CertificateException e) {
			log.error("Could not load certificate(s): " + e.getMessage());
			throw new ExtKeyToolException("Could not load certificate(s): " + e.getMessage());
		} catch (NoSuchProviderException e) {
			log.error("The specified provider is not available.");
			throw new ExtKeyToolException("The specified provider is not available.");
		} catch (IOException ioe) {
			log.error("Could not export key: " + ioe);
			throw new ExtKeyToolException("Could not export key: " + ioe);
		} catch (NoSuchAlgorithmException nse) {
			log.error("Could not save with the installed JCE providers: " + nse);
			throw new ExtKeyToolException("Could not save with the installed JCE providers: " + nse);
		}
	}

	/**
	 * Tries to decipher command line arguments.
	 * 
	 * @throws IllegalArgumentException if arguments are not properly formatted
	 */

	private static Properties parseArguments(String[] args) throws IllegalArgumentException {

		if (args.length < 1) {
			throw new IllegalArgumentException("No arguments found.");
		}
		Properties parsedArguments = new Properties();

		for (int i = 0;(i < args.length) && args[i].startsWith("-"); i++) {

			String flags = args[i];

			//parse actions
			if (flags.equalsIgnoreCase("-exportkey")) {
				parsedArguments.setProperty("command", "exportKey");
			} else if (flags.equalsIgnoreCase("-importkey")) {
				parsedArguments.setProperty("command", "importKey");
			}

			//parse specifiers
			else if (flags.equalsIgnoreCase("-alias")) {
				if (++i == args.length) {
					throw new IllegalArgumentException("The argument -alias requires a parameter");
				}
				parsedArguments.setProperty("alias", args[i]);
			} else if (flags.equalsIgnoreCase("-keyfile")) {
				if (++i == args.length) {
					throw new IllegalArgumentException("The argument -keyfile requires a parameter");
				}
				parsedArguments.setProperty("keyFile", args[i]);
			} else if (flags.equalsIgnoreCase("-certfile")) {
				if (++i == args.length) {
					throw new IllegalArgumentException("The argument -certfile requires a parameter");
				}
				parsedArguments.setProperty("certFile", args[i]);
			} else if (flags.equalsIgnoreCase("-keystore")) {
				if (++i == args.length) {
					throw new IllegalArgumentException("The argument -keystore requires a parameter");
				}
				parsedArguments.setProperty("keyStore", args[i]);
			} else if (flags.equalsIgnoreCase("-storepass")) {
				if (++i == args.length) {
					throw new IllegalArgumentException("The argument -storepass requires a parameter");
				}
				parsedArguments.setProperty("storePass", args[i]);
			} else if (flags.equalsIgnoreCase("-storetype")) {
				if (++i == args.length) {
					throw new IllegalArgumentException("The argument -storetype requires a parameter");
				}
				parsedArguments.setProperty("storeType", args[i]);
			} else if (flags.equalsIgnoreCase("-keypass")) {
				if (++i == args.length) {
					throw new IllegalArgumentException("The argument -keypass requires a parameter");
				}
				parsedArguments.setProperty("keyPass", args[i]);
			} else if (flags.equalsIgnoreCase("-provider")) {
				if (++i == args.length) {
					throw new IllegalArgumentException("The argument -provider requires a parameter");
				}
				parsedArguments.setProperty("provider", args[i]);
			} else if (flags.equalsIgnoreCase("-file")) {
				if (++i == args.length) {
					throw new IllegalArgumentException("The argument -file requires a parameter");
				}
				parsedArguments.setProperty("file", args[i]);
			} else if (flags.equalsIgnoreCase("-algorithm")) {
				if (++i == args.length) {
					throw new IllegalArgumentException("The argument -algorithm requires a parameter");
				}
				parsedArguments.setProperty("keyAlgorithm", args[i]);
			}

			//options
			else if (flags.equalsIgnoreCase("-v")) {
				parsedArguments.setProperty("verbose", "true");
			} else if (flags.equalsIgnoreCase("-rfc")) {
				parsedArguments.setProperty("rfc", "true");
			} else {
				throw new IllegalArgumentException("Unrecognized argument: " + flags);
			}
		}
		if (parsedArguments.getProperty("command", null) == null) {
			throw new IllegalArgumentException("No action specified");
		}
		return parsedArguments;
	}

	/**
	 * Ensures that providers specified on the command line are in fact loaded
	 * into the current environment.
	 * 
	 * @return the name of the provider add, null if no provider was added
	 */

	protected String initProvider(Properties arguments) {

		try {
			if (arguments.getProperty("provider", null) != null) {

				Provider provider = (Provider) Class.forName(arguments.getProperty("provider")).newInstance();
				log.info("Adding Provider to environment: (" + provider.getName() + ")");
				Security.addProvider(provider);
				return provider.getName();
			}
		} catch (Exception e) {
			log.error("Could not load specified jce provider: " + e);
		}
		return null;

	}

	/**
	 * Initializes Log4J logger mode based on command line arguments.
	 */

	protected void startLogger(Properties arguments) {
		Logger root = Logger.getRootLogger();
		if (arguments.getProperty("verbose", null) == null
			|| arguments.getProperty("verbose", null).equals("false")) {
			root.addAppender(new ConsoleAppender(new PatternLayout(PatternLayout.DEFAULT_CONVERSION_PATTERN)));
			root.setLevel(Level.WARN);
		} else {
			root.addAppender(new ConsoleAppender(new PatternLayout(PatternLayout.TTCC_CONVERSION_PATTERN)));
			root.setLevel(Level.DEBUG);
		}
	}

	public static void main(String[] args) {

		try {
			ExtKeyTool tool = new ExtKeyTool();
			Properties arguments = null;
			try {
				arguments = parseArguments(args);
			} catch (IllegalArgumentException iae) {
				System.err.println(
					"Illegal argument specified: " + iae.getMessage() + System.getProperty("line.separator"));
				printUsage(System.err);
				System.exit(1);
			}
			tool.startLogger(arguments);
			String providerName = tool.initProvider(arguments);
			if (providerName != null) {
				arguments.setProperty("providerName", providerName);
			}
			tool.run(arguments);

		} catch (ExtKeyToolException ske) {
			log.fatal("Cannot Perform Operation: " + ske.getMessage() + System.getProperty("line.separator"));
			LogManager.shutdown();
			printUsage(System.err);
		}
	}

	/**
	 * Based on on a set of properties, executes <code>ExtKeyTool</code> actions.
	 * 
	 * @param arguments runtime parameters specified on the command line
	 */

	private void run(Properties arguments) throws ExtKeyToolException {

		//common for all actions
		char[] storePassword = null;
		if (arguments.getProperty("storePass", null) != null) {
			storePassword = arguments.getProperty("storePass").toCharArray();
		}

		String providerName = null;
		if (arguments.getProperty("providerName", null) != null) {
			providerName = arguments.getProperty("providerName");
		} else {
			providerName = "SUN";
		}

		//export key action
		if (arguments.getProperty("command").equals("exportKey")) {

			boolean rfc = false;
			if ("true".equalsIgnoreCase(arguments.getProperty("rfc", null))) {
				rfc = true;
			}

			PrintStream outStream = null;
			if (arguments.getProperty("file", null) != null) {
				try {
					outStream = new PrintStream(new FileOutputStream(arguments.getProperty("file")));
				} catch (FileNotFoundException e) {
					throw new ExtKeyToolException("Could not open output file: " + e);
				}
			} else {
				outStream = System.out;
			}

			try {
				exportKey(
					providerName,
					outStream,
					new FileInputStream(resolveKeyStore(arguments.getProperty("keyStore", null))),
					arguments.getProperty("storeType", null),
					storePassword,
					arguments.getProperty("alias", null),
					resolveKeyPass(arguments.getProperty("keyPass", null), storePassword),
					rfc);
			} catch (FileNotFoundException e) {
				throw new ExtKeyToolException("KeyStore not found.");
			}
			outStream.close();

			//import action
		} else if (arguments.getProperty("command").equals("importKey")) {

			InputStream keyInStream = null;
			if (arguments.getProperty("keyFile", null) != null) {
				try {
					keyInStream = new FileInputStream(arguments.getProperty("keyFile"));
				} catch (FileNotFoundException e) {
					throw new ExtKeyToolException("Could not open key file." + e.getMessage());
				}
			} else {
				throw new IllegalArgumentException("Key file must be specified.");
			}

			InputStream certInStream = null;
			if (arguments.getProperty("certFile", null) != null) {
				try {
					certInStream = new FileInputStream(arguments.getProperty("certFile"));
				} catch (FileNotFoundException e) {
					throw new ExtKeyToolException("Could not open cert file." + e.getMessage());
				}
			} else {
				throw new IllegalArgumentException("Certificate file must be specified.");
			}

			try {
				ByteArrayOutputStream keyStoreOutStream =
					importKey(
						providerName,
						arguments.getProperty("keyAlgorithm", null),
						keyInStream,
						certInStream,
						new FileInputStream(resolveKeyStore(arguments.getProperty("keyStore", null))),
						arguments.getProperty("storeType", null),
						arguments.getProperty("alias", null),
						storePassword,
						resolveKeyPass(arguments.getProperty("keyPass", null), storePassword));

				keyInStream.close();
				// A quick sanity check before we overwrite the old keystore
				if (keyStoreOutStream == null || keyStoreOutStream.size() < 1) {
					throw new ExtKeyToolException("Failed to create keystore: results are null");
				}
				keyStoreOutStream.writeTo(
					new FileOutputStream(resolveKeyStore(arguments.getProperty("keyStore", null))));
				System.out.println("Key import successful.");

			} catch (FileNotFoundException e) {
				throw new ExtKeyToolException("Could not open keystore file." + e.getMessage());
			} catch (IOException e) {
				throw new ExtKeyToolException("Error writing keystore." + e.getMessage());
			}

		} else {
			throw new IllegalArgumentException(
				"This keytool cannot perform the operation: (" + arguments.getProperty("command") + ")");
		}

	}

	/**
	 * Determines the location of the keystore to use when performing the action
	 * 
	 * @return the <code>File</code> representation of the selected keystore
	 */

	protected File resolveKeyStore(String keyStoreLocation)
		throws ExtKeyToolException, FileNotFoundException {

		if (keyStoreLocation == null) {
			keyStoreLocation = System.getProperty("user.home") + File.separator + ".keystore";
		}
		log.debug("Using keystore (" + keyStoreLocation + ")");
		File file = new File(keyStoreLocation);
		if (file.exists() && file.length() == 0) {
			log.error("Keystore file is empty.");
			throw new ExtKeyToolException("Keystore file is empty.");
		}
		return file;
	}

	/**
	 * Decides what password to use for storing/retrieving keys from the keystore.  NOTE: Possible
	 * terminal interaction with the user.
	 * @return a char array containing the password
	 */

	protected char[] resolveKeyPass(String keyPass, char[] storePass) {

		if (keyPass != null) {
			return keyPass.toCharArray();
		} else {
			System.out.println("Enter key password");
			System.out.print("\t(RETURN if same as keystore password):  ");
			System.out.flush();
			try {
				BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
				String passwordInput = reader.readLine();
				passwordInput.trim();
				if (passwordInput != null && !passwordInput.equals("")) {
					return passwordInput.toCharArray();
				}
			} catch (IOException e) {
				log.warn(e.getMessage());
			}
			log.warn("No password specified, defaulting to keystore password.");
			return storePass;
		}
	}

	private static void printUsage(PrintStream out) {

		out.println("extkeytool usage:");
		out.print("-exportkey      [-v] [-rfc] [-alias <alias>] ");
		out.println("[-keystore <keystore>] ");
		out.print("\t     [-storepass <storepass>] ");
		out.println("[-storetype <storetype>]");
		out.print("\t     [-keypass <keypass>] ");
		out.println("[-provider <provider_class_name>] ");
		out.print("\t     [-file <output_file>] ");
		out.println();
		out.println();

		out.print("-importkey      [-v] [-alias <alias>] ");
		out.println("[-keyfile <key_file>]");
		out.print("\t     [-keystore <keystore>] ");
		out.println("[-storepass <storepass>]");
		out.print("\t     [-storetype <storetype>] ");
		out.println("[-keypass <keypass>] ");
		out.print("\t     [-provider <provider_class_name>] ");
		out.println("[-certfile <cert_file>] ");
		out.print("\t     [-algorithm <key_algorithm>] ");
		out.println();

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
		 * Returns an array of the bytes in the container. <p>
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

	/**
	 * Signals that an error was encounted while using <code>ExtKeyTool</code> functions.
	 */

	protected class ExtKeyToolException extends Exception {

		protected ExtKeyToolException(String message) {
			super(message);
		}
	}

	/**
	 * Signals that an error occurred while trying to constuct a
	 * certificate chain.
	 */

	protected class InvalidCertificateChainException extends ExtKeyToolException {

		protected InvalidCertificateChainException(String message) {
			super(message);
		}
	}

}
