/*
 * SchemasDirectoryImpl.java
 * 
 * Find Schemas in a Resource directory
 * 
 * 
 */
package edu.internet2.middleware.shibboleth.xml;

import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import javax.xml.XMLConstants;
import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * @author Howard Gilbert
 */
public class SchemasDirectoryImpl implements Schemas {
    
    private static Logger log = Logger.getLogger(SchemasDirectoryImpl.class);
    
    // The default is the /schemas/ resource directory in the WAR file.
    private String resourcedir = "/schemas/";

    public String getResourcedir() {
        return resourcedir;
    }
    
    /**
     * Allow alternate schema directories to be injected if xsd files
     * cannot coexist within a single schema. For example, SAML 1.0 and
     * 1.1 schemas use the same targetNamespace incompatibly. If you 
     * upgrade from "list of file names" to "list of namespaces", then
     * two incompatible uses of the same namespace have to be stored in
     * two separate schema directories.
     * 
     * @param resourcedir Resource directory from which to load xsd files.
     */
    public void setResourcedir(String resourcedir) {
        this.resourcedir = resourcedir;
    }
    /**
     * Create JAXP 1.3 Schema object from list of namespaces and resource dir
     * 
     * <p>This is an alternate approach to the Schema building logic used in
     * org.opensaml.XML. That module is driven off a list of file names. 
     * This code reads in all the *.xsd files in a directory, indexes them 
     * by the namespace the schema defines, and then is driven off a list
     * of namespaces. This is more more indirect and requires a bit more
     * code, but it is more in line with the actual XSD standard where files
     * and filenames are incidental. It can also be quickly ported to some
     * other schema storage medium (LDAP, Database, ...).</p>
     * 
     * @param namespaces Array of required XML namespaces for validation
     * @param resourcedir Resource directory with schema files ("/schemas/")
     * @return Schema object combining all namespaces.
     */
    public Schema compileSchema(String[] namespaces) {
        
        Schema schema = null;
        
        Map bucket = new HashMap();
        
        // Find a directory of schemas
        // It is a resource in WEB-INF/classes or the same jar file
        // from which this class was loaded.
        URL resource = Parser.class.getResource(resourcedir);
        String path = resource.getPath();
        File dir = new File(path);
        if (!dir.isDirectory()) {
            log.error("Cannot find the schemas resource directory");
            return null;
        }
        
        // for each .xsd file in the directory
        String[] filenames = dir.list();
        int nextsource=0;
        for (int i=0;i<filenames.length;i++) {
            String filename = filenames[i];
            if (!filename.endsWith(".xsd"))
                continue;
            InputStream inputStream =
                    Parser.class.getResourceAsStream(
                        "/schemas/" + filename);
            InputSource insrc = new InputSource(inputStream);
           
            // Non-validating parse to DOM
            Document xsddom = Parser.loadDom(insrc,false);
            
            // Get the target namespace from the root element
            Element ele = xsddom.getDocumentElement();
            if (!ele.getLocalName().equals("schema")) {
                log.error("Schema file wrong root element:"+filename);
                continue;
            }
            String targetNamespace = ele.getAttribute("targetNamespace");
            if (targetNamespace==null) {
                log.error("Schema has no targetNamespace: "+filename);
                continue;
            }
            
            // Put the DOM in the Bucket keyed by namespace
            if (bucket.containsKey(targetNamespace)) {
                log.error("Schema for already defined namespace: "+targetNamespace+" "+filename);
                continue;
            }
            bucket.put(targetNamespace,xsddom);
        }
        // Ok, so now we have a bucket of DOM objects keyed by the 
        // namespaces that they internally declare they define
        
        
        // Now we have a list of Namespaces in the order we need 
        // to process them (imported dependencies first)
        Source[] sources = new Source[namespaces.length];
        for (int i=0;i<namespaces.length;i++) {
            Document doc = (Document) bucket.get(namespaces[i]);
            if (doc==null) 
                log.error("Schema missing for namespace "+namespaces[i]);
            sources[i]= new DOMSource(doc);
        }
        
        // Now compile all the XSD files into a single composite Schema object
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        try {
            schema = factory.newSchema(sources);
        } catch (SAXException e) {
            log.error("Schemas failed to compile, dependencies may have changed "+e);
            System.out.println(e);
        }
        return schema;
        
    }

}
