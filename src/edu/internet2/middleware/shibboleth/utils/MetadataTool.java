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

import jargs.gnu.CmdLineParser;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import org.apache.xml.security.c14n.*;
import org.apache.xml.security.signature.*;
import org.apache.xml.security.transforms.*;
import org.w3c.dom.*;

import edu.internet2.middleware.shibboleth.common.XML;

/**
 *  Signs/verifies/maintains Shibboleth metadata files
 *
 * @author     Scott Cantor
 * @created    June 11, 2002
 */
public class MetadataTool
{
    /**
     *  Signs/verifies/maintains Shibboleth metadata files
     *
     * @param  argv           The command line arguments
     * @exception  Exception  One of about fifty different kinds of possible errors
     */
    public static void main(String args[]) throws Exception {
        // Process the command line.
        CmdLineParser parser = new CmdLineParser();
        CmdLineParser.Option helpOption = parser.addBooleanOption('h', "help");
        CmdLineParser.Option signOption = parser.addBooleanOption('s', "sign");
        CmdLineParser.Option inOption = parser.addStringOption('i', "in");
        CmdLineParser.Option outOption = parser.addStringOption('o', "out");
        CmdLineParser.Option keystoreOption = parser.addStringOption('k', "keystore");
        CmdLineParser.Option aliasOption = parser.addStringOption('a', "alias");
        CmdLineParser.Option pwOption = parser.addStringOption('p', "password");
        CmdLineParser.Option nsOption = parser.addStringOption('x', "ns");
        CmdLineParser.Option nameOption = parser.addStringOption('n', "name");

        try {
            parser.parse(args);
        }
        catch (CmdLineParser.OptionException e) {
            System.err.println(e.getMessage());
            try {
                Thread.sleep(100); //silliness to get error to print first
            }
            catch (InterruptedException ie) {
                //doesn't matter
            }
            printUsage(System.out);
            System.exit(-1);
        }

        Boolean helpEnabled = (Boolean)parser.getOptionValue(helpOption);
        if (helpEnabled != null && helpEnabled.booleanValue()) {
            printUsage(System.out);
            System.exit(0);
        }
        
        Boolean sign = (Boolean)parser.getOptionValue(signOption);
        String keystore = (String)parser.getOptionValue(keystoreOption);
        String pw = (String)parser.getOptionValue(pwOption);
        String alias = (String)parser.getOptionValue(aliasOption);
        String infile = (String)parser.getOptionValue(inOption);
        String outfile = (String)parser.getOptionValue(outOption);
        String ns = (String)parser.getOptionValue(nsOption);
        String name = (String)parser.getOptionValue(nameOption);

        if (infile == null || infile.length() == 0) {
            printUsage(System.out);
            System.exit(1);
        }
        
        if (keystore != null && keystore.length() > 0) {
            if (alias == null || alias.length() == 0) {
                printUsage(System.out);
                System.exit(1);
            }
        }

        PrivateKey privateKey = null;
        Certificate chain[] = null;
        X509Certificate cert = null;
        
        if (sign != null && sign.booleanValue()) {
            if (keystore == null || keystore.length() == 0 || pw == null || pw.length() == 0) {
                printUsage(System.out);
                System.exit(1);
            }
            KeyStore ks = KeyStore.getInstance("JKS");
            FileInputStream fis = new FileInputStream(keystore);
            ks.load(fis, pw.toCharArray());
            privateKey = (PrivateKey)ks.getKey(alias, pw.toCharArray());
            chain = ks.getCertificateChain(alias);
            if (privateKey == null || chain == null) {
                System.err.println("error: couldn't load key or certificate chain from keystore");
                System.exit(1);
            }
        }
        else if (keystore != null && keystore.length() > 0){
            KeyStore ks = KeyStore.getInstance("JKS");
            FileInputStream fis = new FileInputStream(keystore);
            ks.load(fis, null);
            cert = (X509Certificate)ks.getCertificate(alias);
            if (cert == null) {
                System.err.println("error: couldn't load certificate from keystore");
                System.exit(1);
            }
        }
        
        org.opensaml.XML.parserPool.registerSchema(XML.SHIB_NS, XML.SHIB_SCHEMA_ID, new XML.SchemaResolver());
        org.opensaml.XML.parserPool.registerSchema(XML.TRUST_NS, XML.TRUST_SCHEMA_ID, new XML.SchemaResolver());
        
        // Parse file and verify root element.
        Document doc = org.opensaml.XML.parserPool.parse(infile);
        Element e = doc.getDocumentElement();
        if (ns != null && name != null && !org.opensaml.XML.isElementNamed(e,ns,name)) {
            System.err.println("error: root element did not match ns and name parameters");
            System.exit(1);
        }
        else if (!org.opensaml.XML.isElementNamed(e,XML.SHIB_NS,"SiteGroup") &&
        		    !org.opensaml.XML.isElementNamed(e,XML.SHIB_NS,"Trust") &&
					!org.opensaml.XML.isElementNamed(e,XML.TRUST_NS,"Trust")) {
            System.err.println("error: root element must be shib:SiteGroup, shib:Trust, or trust:Trust");
            System.exit(1);
        }

        if (sign != null && sign.booleanValue()) {
            // Remove any existing signature.
            Element old = org.opensaml.XML.getLastChildElement(e, org.opensaml.XML.XMLSIG_NS, "Signature");
            if (old != null)
                e.removeChild(old);

            // Create new signature.
            XMLSignature sig = new XMLSignature(doc, null, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
            Transforms transforms = new Transforms(doc);
            transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
            transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
            sig.addDocument("", transforms, org.apache.xml.security.utils.Constants.ALGO_ID_DIGEST_SHA1);
            for (int i=0; i < chain.length; i++)
            	sig.addKeyInfo((X509Certificate)chain[i]);
            e.appendChild(sig.getElement());
            sig.sign(privateKey);
        }
        else if (cert != null) {
            Element sigElement = org.opensaml.XML.getLastChildElement(e, org.opensaml.XML.XMLSIG_NS, "Signature");
            if (sigElement == null) {
                System.err.println("error: file was not signed");
                System.exit(1);
            }
            XMLSignature sig = new XMLSignature(sigElement, null);
            if (!sig.checkSignatureValue(cert)) {
                System.err.println("error: signature on file did not verify");
                System.exit(1);
            }
        }
        
        OutputStream out = null;
        Canonicalizer c = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS);
        if (outfile != null && outfile.length() > 0) {
            out = new FileOutputStream(outfile);
            out.write(c.canonicalizeSubtree(doc));
            out.close();
        }
        else {
        	System.out.write(c.canonicalizeSubtree(doc));
        }
    }

    private static void printUsage(PrintStream out)
    {

        out.println("usage: java edu.internet2.middleware.shibboleth.utils.MetadataTool");
        out.println();
        out.println("when signing:   -i <uri> -s -k <keystore> -a <alias> -p <pass> [-o <outfile>]");
        out.println("when updating:  -i <uri> [-k <keystore> -a <alias> -o <outfile>]");
        out.println("  -i,--in              input file or url");
        out.println("  -k,--keystore        pathname of Java keystore file");
        out.println("  -a,--alias           alias of signing or verification key");
        out.println("  -p,--password        keystore/key password");
        out.println("  -o,--outfile         write signed copy to this file instead of stdout");
        out.println("  -s,--sign            sign the input file and write out a signed version");
        out.println("  -h,--help            print this message");
        out.println("  -x,--ns              XML namespace of root element");
        out.println("  -n,--name            name of root element");
        out.println();
        System.exit(1);
    }
}

