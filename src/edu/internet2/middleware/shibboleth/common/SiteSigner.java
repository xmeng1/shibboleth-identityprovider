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

package edu.internet2.middleware.shibboleth.common;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import org.apache.xml.security.c14n.*;
import org.apache.xml.security.signature.*;
import org.apache.xml.security.transforms.*;
import org.w3c.dom.*;

/**
 *  Validates and signs a Shibboleth site file
 *
 * @author     Scott Cantor
 * @created    June 11, 2002
 */
public class SiteSigner
{
    /**
     *  Validates and signs a Shibboleth site file
     *
     * @param  argv           The command line arguments
     * @exception  Exception  One of about fifty different kinds of possible errors
     */
    public static void main(String argv[])
        throws Exception
    {
        if (argv.length == 0)
            printUsage();

        String keystore = null;
        String ks_pass = "";
        String key_alias = null;
        String key_pass = "";
        String outfile = null;
        String arg = null;

        // process arguments
        for (int i = 0; i < argv.length; i++)
        {
            arg = argv[i];
            if (arg.startsWith("-"))
            {
                String option = arg.substring(1);
                if (option.equals("k"))
                {
                    if (++i == argv.length)
                    {
                        System.err.println("error: Missing argument to -k option");
                        System.exit(1);
                    }
                    keystore = argv[i];
                    continue;
                }
                else if (option.equals("P"))
                {
                    if (++i == argv.length)
                    {
                        System.err.println("error: Missing argument to -P option");
                        System.exit(1);
                    }
                    ks_pass = argv[i];
                    continue;
                }
                else if (option.equals("a"))
                {
                    if (++i == argv.length)
                    {
                        System.err.println("error: Missing argument to -a option");
                        System.exit(1);
                    }
                    key_alias = argv[i];
                    continue;
                }
                else if (option.equals("p"))
                {
                    if (++i == argv.length)
                    {
                        System.err.println("error: Missing argument to -p option");
                        System.exit(1);
                    }
                    key_pass = argv[i];
                    continue;
                }
                else if (option.equals("o"))
                {
                    if (++i == argv.length)
                    {
                        System.err.println("error: Missing argument to -o option");
                        System.exit(1);
                    }
                    outfile = argv[i];
                    continue;
                }
                else if (option.equals("h"))
                    printUsage();
            }
        }

        if (keystore == null || keystore.length() == 0 ||
            key_alias == null || key_alias.length() == 0)
            printUsage();
            
        if (key_pass == null)
            key_pass = ks_pass;

        KeyStore ks = KeyStore.getInstance("JKS");
        FileInputStream fis = new FileInputStream(keystore);
        ks.load(fis, ks_pass.toCharArray());
        PrivateKey privateKey = (PrivateKey)ks.getKey(key_alias, key_pass.toCharArray());
        X509Certificate cert = (X509Certificate)ks.getCertificate(key_alias);
        if (privateKey == null || cert == null)
        {
            System.err.println("error: couldn't load key or certificate");
            System.exit(1);
        }

        Document doc = org.opensaml.XML.parserPool.parse(arg);
        Element e = doc.getDocumentElement();
        if (!XML.SHIB_NS.equals(e.getNamespaceURI()) || !"Sites".equals(e.getLocalName()))
        {
            System.err.println("error: root element must be shib:Sites");
            System.exit(1);
        }

        NodeList siglist = doc.getElementsByTagNameNS(org.opensaml.XML.XMLSIG_NS, "Signature");
        if (siglist.getLength() > 0)
        {
            System.err.println("error: file already signed");
            System.exit(1);
        }

        XMLSignature sig = new XMLSignature(doc, null, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        sig.addDocument("", transforms, org.apache.xml.security.utils.Constants.ALGO_ID_DIGEST_SHA1);
        sig.addKeyInfo(cert);
        e.appendChild(sig.getElement());
        sig.sign(privateKey);

        OutputStream out = null;
        if (outfile != null && outfile.length() > 0)
            out = new FileOutputStream(outfile);
        else
            out = System.out;

        Canonicalizer c = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS);
        out.write(c.canonicalizeSubtree(doc));

        if (outfile != null && outfile.length() > 0)
            out.close();
    }

    private static void printUsage()
    {

        System.err.println("usage: java edu.internet2.middleware.shibboleth.commmon.SiteSigner (options) uri");
        System.err.println();

        System.err.println("required options:");
        System.err.println("  -k keystore   pathname of Java keystore file");
        System.err.println("  -a key alias  alias of signing key");
        System.err.println();
        System.err.println("optional options:");
        System.err.println("  -P password   keystore password");
        System.err.println("  -p password   private key password");
        System.err.println("  -o outfile    write signed copy to this file instead of stdout");
        System.err.println("  -h            print this message");
        System.err.println();
        System.exit(1);
    }

    static
    {
        Init.init();
    }
}

