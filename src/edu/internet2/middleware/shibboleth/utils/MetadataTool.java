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

import jargs.gnu.CmdLineParser;

import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.xml.security.c14n.*;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.signature.*;
import org.apache.xml.security.transforms.*;
import org.w3c.dom.*;

import edu.internet2.middleware.shibboleth.common.XML;
import edu.internet2.middleware.shibboleth.xml.Parser;

/**
 * Signs/verifies/maintains Shibboleth metadata files
 * 
 * @author Scott Cantor
 * @created June 11, 2002
 */
public class MetadataTool {

	/**
	 * Signs/verifies/maintains Shibboleth metadata files
	 * 
	 * @param argv
	 *            The command line arguments
	 * @exception Exception
	 *                One of about fifty different kinds of possible errors
	 */
	public static void main(String args[]) throws Exception {

		// Process the command line.
		CmdLineParser parser = new CmdLineParser();
		CmdLineParser.Option helpOption = parser.addBooleanOption('h', "help");
		CmdLineParser.Option signOption = parser.addBooleanOption('s', "sign");
		CmdLineParser.Option noverifyOption = parser.addBooleanOption('N', "noverify");
		CmdLineParser.Option inOption = parser.addStringOption('i', "in");
		CmdLineParser.Option outOption = parser.addStringOption('o', "out");
		CmdLineParser.Option keystoreOption = parser.addStringOption('k', "keystore");
		CmdLineParser.Option aliasOption = parser.addStringOption('a', "alias");
		CmdLineParser.Option pwOption = parser.addStringOption('p', "password");
		CmdLineParser.Option nsOption = parser.addStringOption('x', "ns");
		CmdLineParser.Option nameOption = parser.addStringOption('n', "name");
		CmdLineParser.Option idOption = parser.addStringOption('I', "id");
		CmdLineParser.Option debugOption = parser.addBooleanOption('d', "debug");

		Boolean debugEnabled = ((Boolean) parser.getOptionValue(debugOption));
		boolean debug = false;
		if (debugEnabled != null) {
			debug = debugEnabled.booleanValue();
		}
		configureLogging(debug);

		try {
			parser.parse(args);
		} catch (CmdLineParser.OptionException e) {
			System.err.println(e.getMessage());
			try {
				Thread.sleep(100); // silliness to get error to print first
			} catch (InterruptedException ie) {
				// doesn't matter
			}
			printUsage(System.out);
			System.exit(-1);
		}

		Boolean helpEnabled = (Boolean) parser.getOptionValue(helpOption);
		if (helpEnabled != null && helpEnabled.booleanValue()) {
			printUsage(System.out);
			System.exit(0);
		}

		Boolean sign = (Boolean) parser.getOptionValue(signOption);
		Boolean noverify = (Boolean) parser.getOptionValue(noverifyOption);
		String keystore = (String) parser.getOptionValue(keystoreOption);
		String pw = (String) parser.getOptionValue(pwOption);
		String alias = (String) parser.getOptionValue(aliasOption);
		String infile = (String) parser.getOptionValue(inOption);
		String outfile = (String) parser.getOptionValue(outOption);
		String ns = (String) parser.getOptionValue(nsOption);
		String name = (String) parser.getOptionValue(nameOption);
		String id = (String) parser.getOptionValue(idOption);

		if (infile == null || infile.length() == 0) {
			printUsage(System.out);
			System.exit(-1);
		}

		if (keystore != null && keystore.length() > 0) {
			if (alias == null || alias.length() == 0) {
				printUsage(System.out);
				System.exit(-1);
			}
		}

		PrivateKey privateKey = null;
		Certificate chain[] = null;
		X509Certificate cert = null;

		if (sign != null && sign.booleanValue()) {
			if (keystore == null || keystore.length() == 0 || pw == null || pw.length() == 0) {
				printUsage(System.out);
				System.exit(-1);
			}
			KeyStore ks = KeyStore.getInstance("JKS");
			FileInputStream fis = new FileInputStream(keystore);
			ks.load(fis, pw.toCharArray());
			privateKey = (PrivateKey) ks.getKey(alias, pw.toCharArray());
			chain = ks.getCertificateChain(alias);
			if (privateKey == null || chain == null) {
				System.err.println("error: couldn't load key or certificate chain from keystore");
				System.exit(1);
			}
		} else if (keystore != null && keystore.length() > 0) {
			KeyStore ks = KeyStore.getInstance("JKS");
			FileInputStream fis = new FileInputStream(keystore);
			ks.load(fis, null);
			cert = (X509Certificate) ks.getCertificate(alias);
			if (cert == null) {
				System.err.println("error: couldn't load certificate from keystore");
				System.exit(1);
			}
		} else if (noverify == null || !noverify.booleanValue()) {
			printUsage(System.out);
			System.exit(-1);
		}

		// Parse file and verify root element.
		Document doc = Parser.loadDom(new URL(new URL("file:"),infile), true);
		if (doc == null) {
			System.out.println("error: unable to read in file (" + infile + ")");
			System.exit(-1);
		}
		Element e = doc.getDocumentElement();
		if (ns != null && name != null && !org.opensaml.XML.isElementNamed(e, ns, name)) {
			System.err.println("error: root element did not match ns and name parameters");
			System.exit(1);
		} else if (!org.opensaml.XML.isElementNamed(e, XML.SHIB_NS, "SiteGroup")
				&& !org.opensaml.XML.isElementNamed(e, XML.SHIB_NS, "Trust")
				&& !org.opensaml.XML.isElementNamed(e, XML.TRUST_NS, "Trust")
				&& !org.opensaml.XML.isElementNamed(e, XML.SAML2META_NS, "EntityDescriptor")
				&& !org.opensaml.XML.isElementNamed(e, XML.SAML2META_NS, "EntitiesDescriptor")) {
			System.err.println("error: root element must be SiteGroup, Trust, EntitiesDescriptor, or EntityDescriptor");
			System.exit(1);
		}

		if (id != null) {
			e = doc.getElementById(id);
			if (e == null) {
				System.err.println("error: no element with ID (" + id + ") found in document");
				System.exit(1);
			}
		}

		if (sign != null && sign.booleanValue()) {
			// Remove any existing signature.
			Element old = org.opensaml.XML.getFirstChildElement(e, org.opensaml.XML.XMLSIG_NS, "Signature");
			if (old != null) e.removeChild(old);

			// Create new signature.
			XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1,
					Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS);
			Transforms transforms = new Transforms(doc);
			transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
			transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_WITH_COMMENTS);
			sig.addDocument((id == null) ? ("") : ("#" + id), transforms,
					org.apache.xml.security.utils.Constants.ALGO_ID_DIGEST_SHA1);

			// Add any X.509 certificates provided.
			if (chain != null && chain.length > 0) {
				X509Data x509 = new X509Data(doc);
				for (int i = 0; i < chain.length; i++) {
					if (chain[i] instanceof X509Certificate) x509.addCertificate((X509Certificate) chain[i]);
				}
				KeyInfo keyinfo = new KeyInfo(doc);
				keyinfo.add(x509);
				sig.getElement().appendChild(keyinfo.getElement());
			}

			if (XML.SAML2META_NS.equals(e.getNamespaceURI())) e.insertBefore(sig.getElement(), e.getFirstChild());
			else e.appendChild(sig.getElement());
			sig.sign(privateKey);
		} else {
			// Check the root element's signature or the particular one specified.
			Element sigElement = org.opensaml.XML.getLastChildElement(e, org.opensaml.XML.XMLSIG_NS, "Signature");
			boolean v = (noverify == null || !noverify.booleanValue());
			if (v) {
				if (sigElement == null) {
					System.err.println("error: file is not signed");
					System.exit(1);
				}
				if (!verifySignature(doc, sigElement, cert)) {
					System.err.println("error: signature did not verify");
					System.exit(1);
				}
			} else if (sigElement != null) {
				System.err.println("verification of signer disabled, make sure you trust the source of this file!");
				if (!verifySignature(doc, sigElement, cert)) {
					System.err.println("error: signature did not verify");
					System.exit(1);
				}
			} else {
				System.err.println("verification disabled, and file is unsigned!");
			}

			// Check all the signatures.
			NodeList nlist = e.getElementsByTagNameNS(org.opensaml.XML.XMLSIG_NS, "Signature");
			for (int i = 0; i < nlist.getLength(); i++) {
				if (!verifySignature(doc, (Element) nlist.item(i), cert)) {
					System.err.println("error: signature did not verify");
					System.exit(1);
				}
			}
		}

		Canonicalizer c = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS);
		if (outfile != null && outfile.length() > 0) {
			OutputStream out = new FileOutputStream(outfile);
			out.write(c.canonicalizeSubtree(doc));
			out.close();
		} else {
			// For some reason, using write(byte[]) doesn't work.
			System.out.print(new String(c.canonicalizeSubtree(doc)));
		}
	}

	private static boolean verifySignature(Document doc, Element sigNode, X509Certificate cert) throws Exception {

		XMLSignature sig = new XMLSignature(sigNode, "");

		// Validate the signature content by checking for specific Transforms.
		boolean valid = false;
		SignedInfo si = sig.getSignedInfo();
		if (si.getLength() == 1) {
			Reference ref = si.item(0);
			if (ref.getURI() == null || ref.getURI().equals("")
					|| ref.getURI().equals("#" + ((Element) sigNode.getParentNode()).getAttributeNS(null, "ID"))) {
				Transforms trans = ref.getTransforms();
				for (int i = 0; i < trans.getLength(); i++) {
					if (trans.item(i).getURI().equals(Transforms.TRANSFORM_ENVELOPED_SIGNATURE)) valid = true;
					else if (!trans.item(i).getURI().equals(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS)
							&& !trans.item(i).getURI().equals(Transforms.TRANSFORM_C14N_EXCL_WITH_COMMENTS)) {
						valid = false;
						break;
					}
				}
			}
		}

		if (!valid) {
			System.err.println("error: signature profile was invalid");
			return false;
		}

		if (cert != null) return sig.checkSignatureValue(cert);
		else return sig.checkSignatureValue(sig.getKeyInfo().getPublicKey());
	}

	private static void printUsage(PrintStream out) {

		out.println("usage: java edu.internet2.middleware.shibboleth.utils.MetadataTool");
		out.println();
		out.println("when signing:   -i <uri> -s -k <keystore> -a <alias> -p <pass> [-o <outfile>]");
		out.println("when updating:  -i <uri> [-k <keystore> -a <alias> OR -N ] [-o <outfile>]");
		out.println("  -i,--in              input file or url");
		out.println("  -k,--keystore        pathname of Java keystore file");
		out.println("  -a,--alias           alias of signing or verification key");
		out.println("  -p,--password        keystore/key password");
		out.println("  -o,--outfile         write signed copy to this file instead of stdout");
		out.println("  -s,--sign            sign the input file and write out a signed version");
		out.println("  -N,--noverify        allows update of file without signature check");
		out.println("  -h,--help            print this message");
		out.println("  -x,--ns              XML namespace of root element");
		out.println("  -n,--name            name of root element");
		out.println("  -I,--id              ID attribute value of element to sign");
		out.println("  -d, --debug          run in debug mode");
		out.println();
		System.exit(1);
	}

	private static void configureLogging(boolean debugEnabled) {

		ConsoleAppender rootAppender = new ConsoleAppender();
		rootAppender.setWriter(new PrintWriter(System.err));
		rootAppender.setName("stdout");
		Logger.getRootLogger().addAppender(rootAppender);

		if (debugEnabled) {
			Logger.getRootLogger().setLevel(Level.DEBUG);
			rootAppender.setLayout(new PatternLayout("%-5p %-41X{serviceId} %d{ISO8601} (%c:%L) - %m%n"));
		} else {
			Logger.getRootLogger().setLevel(Level.INFO);
			Logger.getLogger("edu.internet2.middleware.shibboleth.aa.attrresolv").setLevel(Level.WARN);
			rootAppender.setLayout(new PatternLayout(PatternLayout.TTCC_CONVERSION_PATTERN));
		}
		Logger.getLogger("org.apache.xml.security").setLevel(Level.OFF);
	}
}
