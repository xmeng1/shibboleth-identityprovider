package edu.internet2.middleware.shibboleth.shire;

import edu.internet2.middleware.shibboleth.common.*;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Vector;
import javax.xml.parsers.*;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.*;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.*;
import org.xml.sax.SAXException;

/**
 *  OriginSiteMapper implementation using an XML file to populate an in-memory
 *  database from an optionally-signed XML file
 *
 * @author     Scott Cantor
 * @created    June 8, 2002
 */
public class XMLOriginSiteMapper implements OriginSiteMapper
{

    private HashMap originSites = null;
    private HashMap hsKeys = null;
    private KeyStore ks = null;

    /**
     *  Constructor for the XMLOriginSiteMapper object
     *
     * @param  registryURI               Tells where to find/download origin
     *      site registry file
     * @param  verifyKey                 Optional key to verify signature with
     * @param  ks                        Key store containing the trusted roots
     *      to be used by SHIRE
     * @exception  SAXException          Raised if the registry file cannot be
     *      parsed and loaded
     * @exception  java.io.IOException   Description of Exception
     * @exception  XMLSecurityException  Description of Exception
     */
    public XMLOriginSiteMapper(String registryURI, Key verifyKey, KeyStore ks)
        throws SAXException, java.io.IOException, XMLSecurityException
    {
        this.ks = ks;

        DocumentBuilder builder = null;
        try
        {
            builder = org.opensaml.XML.parserPool.get();
            Document doc = builder.parse(registryURI);
            Element e = doc.getDocumentElement();
            if (!XML.SHIB_NS.equals(e.getNamespaceURI()) || !"Sites".equals(e.getLocalName()))
                throw new SAXException("XMLOriginSiteMapper() requires shib:Sites as root element");

            // Loop over the OriginSite elements.
            NodeList nlist = e.getElementsByTagNameNS(XML.SHIB_NS,"OriginSite");
            for (int i=0; nlist!=null && i<nlist.getLength(); i++)
            {
                String os_name = ((Element)nlist.item(i)).getAttributeNS(null, "Name").trim();
                if (os_name.length() == 0)
                    continue;

                OriginSite os_obj = new OriginSite(os_name);
                originSites.put(os_name, os_obj);

                Node os_child = nlist.item(i).getFirstChild();
                while (os_child != null)
                {
                    if (os_child.getNodeType() != Node.ELEMENT_NODE)
                    {
                        os_child = os_child.getNextSibling();
                        continue;
                    }

                    // Process the various kinds of OriginSite children that we care about...
                    if (XML.SHIB_NS.equals(os_child.getNamespaceURI()) && "HandleService".equals(os_child.getLocalName()))
                    {
                        String hs_name = ((Element)os_child).getAttributeNS(null, "Name").trim();
                        if (hs_name.length() > 0)
                        {
                            os_obj.handleServices.add(hs_name);

                            // Check for KeyInfo.
                            Node ki = os_child.getFirstChild();
                            while (ki != null && ki.getNodeType() != Node.ELEMENT_NODE)
                                ki = ki.getNextSibling();
                            if (ki != null && org.opensaml.XML.XMLSIG_NS.equals(ki.getNamespaceURI()) &&
                                "KeyInfo".equals(ki.getLocalName()))
                            {
                                try
                                {
                                    KeyInfo kinfo = new KeyInfo((Element)ki, null);
                                    PublicKey pubkey = kinfo.getPublicKey();
                                    if (pubkey != null)
                                        hsKeys.put(hs_name, pubkey);
                                }
                                catch (XMLSecurityException exc)
                                {
                                }
                            }
                        }
                    }
                    else if (XML.SHIB_NS.equals(os_child.getNamespaceURI()) && "Domain".equals(os_child.getLocalName()))
                    {
                        String dom = os_child.getFirstChild().getNodeValue().trim();
                        if (dom.length() > 0)
                            os_obj.domains.add(dom);
                    }
                    os_child = os_child.getNextSibling();
                }
            }

            Node n=e.getLastChild();
            while (n!=null && n.getNodeType()!=Node.ELEMENT_NODE)
                n=n.getPreviousSibling();

            boolean verified = false;
            if (n!=null && org.opensaml.XML.XMLSIG_NS.equals(n.getNamespaceURI()) && "Signature".equals(n.getLocalName()))
            {
                XMLSignature sig = new XMLSignature((Element)n, null);

                // First, we verify that what is signed is what we expect.
                SignedInfo sinfo = sig.getSignedInfo();
                if (sinfo.getCanonicalizationMethodURI().equals(Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS) ||
                    sinfo.getCanonicalizationMethodURI().equals(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS))
//                        sinfo.getCanonicalizationMethodURI().equals(Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS) ||
//                        sinfo.getCanonicalizationMethodURI().equals(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS))
                {
                    Reference ref = sinfo.item(0);
                    if (ref.getURI() == null || ref.getURI().equals(""))
                    {
                        Transforms trans = ref.getTransforms();
                        if (trans.getLength() == 1 && trans.item(0).getURI().equals(Transforms.TRANSFORM_ENVELOPED_SIGNATURE))
                        {
                            // Lastly, we check the signature value.
                            if (sig.checkSignatureValue(verifyKey))
                                verified = true;
                        }
                    }
                }
            }

            if (verifyKey != null && !verified)
                throw new XMLSecurityException("XMLOriginSiteMapper() unable to verify signature on registry file");
        }
        catch (ParserConfigurationException pce)
        {
            throw new DOMException(DOMException.NOT_SUPPORTED_ERR, "XMLOriginSiteMapper() parser configuration error");
        }
        finally
        {
            if (builder != null)
                org.opensaml.XML.parserPool.put(builder);
        }
    }

    /**
     *  Provides an iterator over the trusted Handle Services for the specified
     *  origin site
     *
     * @param  originSite  The DNS name of the origin site to query
     * @return             An iterator over the Handle Service DNS names
     */
    public Iterator getHandleServiceNames(String originSite)
    {
        OriginSite o = (OriginSite)originSites.get(originSite);
        if (o != null)
            return o.handleServices.iterator();
        return null;
    }

    /**
     *  Returns a preconfigured key to use in verifying a signature created by
     *  the specified HS<P>
     *
     *  Any key returned is implicitly trusted and a certificate signed by
     *  another trusted entity is not sought or required
     *
     * @param  handleService  Description of Parameter
     * @return                A trusted key (probably public but could be
     *      secret) or null
     */
    public Key getHandleServiceKey(String handleService)
    {
        return (Key)hsKeys.get(handleService);
    }

    /**
     *  Provides an iterator over the security domain expressions for which the
     *  specified origin site is considered to be authoritative
     *
     * @param  originSite  The DNS name of the origin site to query
     * @return             An iterator over a set of regular expression strings
     */
    public Iterator getSecurityDomains(String originSite)
    {
        OriginSite o = (OriginSite)originSites.get(originSite);
        if (o != null)
            return o.domains.iterator();
        return null;
    }

    /**
     *  Gets a key store containing certificate entries that are trusted to sign
     *  Handle Service certificates that are encountered during processing<P>
     *
     *
     *
     * @return    A key store containing trusted certificate issuers
     */
    public KeyStore getTrustedRoots()
    {
        return ks;
    }

    private class OriginSite
    {

        private Vector domains = null;
        private Vector handleServices = null;

        private OriginSite(String name)
        {
            domains = new Vector();
            domains.add(name);
            handleServices = new Vector();
        }
    }
}

