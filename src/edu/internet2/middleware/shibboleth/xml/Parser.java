/*
 * Parser.java
 * 
 * Validating and non-validating XML parsing using JAXP 1.3.
 * 
 * Previous versions of the code directly used the Xerces DOMParser
 * class. This class has been hidden in the Sun XML stack, and the
 * public interface is to use DocumentBuilderFactory. This module 
 * requires the DOM 3 and JAXP 1.3 support built into J2SE 5.0 and
 * distributed separately for earlier releases of Java from
 * https://jaxp.dev.java.net/. It should also work with Xerces 2.7.0
 * when that release becomes available.
 * 
 * The org.opensaml.XML class already has most of the parsing code,
 * but it uses a subset of the required Schemas. Here we build a
 * wider Schema object, set it as the default SAML schema (because
 * some Shibboleth namespace fields appear in SAML statements), and
 * demand that Schema for every parser (DocumentBuilder) we request.
 * 
 * Currently, this class exposes static methods. Should a real 
 * framework be installed, it would become a singleton object.
 */
package edu.internet2.middleware.shibboleth.xml;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.validation.Schema;

import org.apache.log4j.Logger;
import org.opensaml.SAMLException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * Obtain schema validating and non-validating XML parsers.
 * 
 * @author Howard Gilbert
 */
public class Parser {
    private static Logger log = Logger.getLogger(Parser.class);
    
    
    /**
     * All the namespaces used by any part of Shibboleth
     * 
     * Note: The current Schema compiler requires that dependencies
     * (imports) be listed before the namespace of the schema
     * that imports them.
     */
    private static String[] namespaces = new String[]{
            "http://www.w3.org/2000/09/xmldsig#",  
            "http://www.w3.org/2001/04/xmlenc#",
            "urn:oasis:names:tc:SAML:1.0:assertion",
            "urn:oasis:names:tc:SAML:2.0:assertion",
            "http://www.w3.org/XML/1998/namespace",
            "http://schemas.xmlsoap.org/soap/envelope/",
            "urn:mace:shibboleth:credentials:1.0",
            "urn:oasis:names:tc:SAML:1.0:protocol",
            "urn:oasis:names:tc:SAML:2.0:protocol",
            "urn:mace:shibboleth:namemapper:1.0",
            "urn:mace:shibboleth:origin:1.0",
            "urn:mace:shibboleth:arp:1.0",
            "urn:mace:shibboleth:resolver:1.0",
            "urn:mace:shibboleth:target:config:1.0",
            "urn:mace:shibboleth:trust:1.0",
            "urn:mace:shibboleth:metadata:1.0",
            "urn:mace:shibboleth:1.0",
            "http://schemas.xmlsoap.org/soap/envelope/",
            "urn:oasis:names:tc:SAML:2.0:metadata"
      };
    
    // If there were a real Framework here (like Spring) then
    // the schemaBuilder would be inserted 
    private static Schemas schemaBuilder = new SchemasDirectoryImpl();
    private static Schema schema = schemaBuilder.compileSchema(namespaces);
    
    /**
     * Load a DOM from a wrapped byte stream.
     * 
     * @param ins InputSource The XML document
     * @param validate If true, use Schema. Otherwise, its raw XML.
     * @return A DOM 3 tree
     */
    public static Document loadDom(InputSource ins, boolean validate) {
        Document doc=null;
        log.info("Loading XML from (" + ins.getSystemId() + ")"
                + (validate?" with Schema validation":"")
                );
        try {
            if (validate)
                doc = org.opensaml.XML.parserPool.parse(ins,schema);
            else
                doc = org.opensaml.XML.parserPool.parse(ins,null);
            
        } catch (SAXException e) {
            log.error("Error in XML configuration file"+e);
            return null;
        } catch (IOException e) {
            log.error("Error accessing XML configuration file"+e);
            return null;
        } catch (SAMLException e) {
            log.error("Error with XML parser "+e);
            return null;
       }
        
        return doc;
    }
    
    
    /**
     * A dummy class that pretends to be an old Xerces DOMParser
     * to simplify conversion of existing code.
     */
    public static class DOMParser {
        Document doc = null;
        boolean validate = false;
        
        public DOMParser(boolean validate) {
            this.validate=validate;
        }
        
        public Document parse(InputSource ins) throws SAXException, IOException {
            doc = loadDom(ins,true);
            return doc;
        }
        
        public Document getDocument() {
            return doc;
        }
    }
    
    /**
     * Write a DOM out to a character stream (for debugging and logging)
     * 
     * @param dom The DOM tree to write
     * @return A string containing the XML in character form.
     */
    public static String serialize(Node dom) {
        String ret = null;
        
        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = null;
        DOMSource source = new DOMSource(dom);
        try {
            transformer = factory.newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        } catch (TransformerConfigurationException e) {
            return null;
        }
        StringWriter stringWriter = new StringWriter();
        StreamResult result = new StreamResult(stringWriter);
        try {
            transformer.transform(source, result);
        } catch (TransformerException e1) {
            return null;
        }
        return stringWriter.toString();
    }
    
    /**
     * Version of loadDom where the file is specified as a resource name
     * 
     * @param configFilePath input resource
     * @param validate if true, use Schema
     * @return DOM tree
     */
    public static Document loadDom(String configFilePath,boolean validate) 
    {
        InputSource insrc;
        String schemaCannonicalFilePath;
       try {
            InputStream resourceAsStream = Parser.class.getResourceAsStream(configFilePath);
            insrc = new InputSource(resourceAsStream);
            insrc.setSystemId(configFilePath);
        } catch (Exception e1) {
            log.error("Configuration file "+configFilePath+" could not be located.");
            return null;
        }
        
        return loadDom(insrc,validate); // Now pass on to the main routine
        
    }
    
    /**
     * Override the OpenSAML default schema from SAML 1.1 to 
     * SAML 1.1 plus Shibboleth (and some SAML 2.0).
     */
    static {
        org.opensaml.XML.parserPool.setDefaultSchema(schema);
    }
    
}