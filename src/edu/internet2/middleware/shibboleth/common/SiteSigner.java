package edu.internet2.middleware.shibboleth.common;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import javax.xml.parsers.*;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.*;
import org.apache.xml.security.signature.*;
import org.apache.xml.security.transforms.*;
import org.w3c.dom.*;

/**
 *  Description of the Class
 *
 * @author     cantor
 * @created    June 11, 2002
 */
public class SiteSigner
{
    /**
     *  Description of the Method
     *
     * @param  argv           Description of Parameter
     * @exception  Exception  Description of Exception
     */
    public static void main(String argv[])
        throws Exception
    {
        if (argv.length == 0)
            printUsage();

        String keystore = null;
        String ks_pass = null;
        String key_alias = null;
        String cert_alias = null;
        String key_pass = null;
        String outfile = null;
        String arg=null;

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
                else if (option.equals("c"))
                {
                    if (++i == argv.length)
                    {
                        System.err.println("error: Missing argument to -c option");
                        System.exit(1);
                    }
                    cert_alias = argv[i];
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

        if (keystore == null || keystore.length() == 0 || key_alias == null || key_alias.length() == 0 ||
            cert_alias == null || cert_alias.length() == 0)
            printUsage();

        KeyStore ks = KeyStore.getInstance("JKS");
        FileInputStream fis = new FileInputStream(keystore);
        ks.load(fis, ks_pass == null ? null : ks_pass.toCharArray());
        PrivateKey privateKey = (PrivateKey)ks.getKey(key_alias, key_pass == null ? null : key_pass.toCharArray());
        X509Certificate cert = (X509Certificate)ks.getCertificate(cert_alias);
        if (privateKey == null || cert == null)
        {
            System.err.println("error: couldn't load key or certificate");
            System.exit(1);
        }

        DocumentBuilder builder = org.opensaml.XML.parserPool.get();
        Document doc = builder.parse(arg);
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
        c.setNamespaceAware(true);
        out.write(c.canonicalize(doc));

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
        System.err.println("  -c cert alias alias of signing cert");
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
        org.apache.xml.security.Init.init();
    }
}

