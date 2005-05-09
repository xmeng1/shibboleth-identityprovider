/*
 * SchemasDirectoryImpl.java
 * 
 * Find Schemas as a list of resource files.
 * 
 * <p>Java resources are files found in the Classpath of the current
 * ClassLoader. They may be in directories on disk, in jar files, or
 * elsewhere. This class must be passed a list of resource names, but
 * it uses the Java runtime to actually locate the xsd data.
 */
package edu.internet2.middleware.shibboleth.xml;

import java.io.InputStream;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

/**
 * @author Howard Gilbert
 */
public class SchemasResourceListImpl extends SchemaStore {
    
    private static Logger log = Logger.getLogger(SchemasDirectoryImpl.class);
    
    private String resourceprefix = "/schemas/";
    private String[] resourceNames = null;

    /**
     * @param resourcedir
     */
    public SchemasResourceListImpl(String resourcedir, String[] resources) {
        this.resourceprefix = resourcedir;
        this.resourceNames = resources;
        this.loadBucket();
    }
    
   
    private void loadBucket() {
		// for each .xsd file in the directory
		int nextsource=0;
		for (int i=0;i<resourceNames.length;i++) {
            String filename = resourceNames[i];
            if (!filename.endsWith(".xsd")) {
                log.error(filename + " doesn't end in .xsd, ignoring it.");
                continue;
            }
            String resourceName = resourceprefix+filename;
            InputStream inputStream =
                    Parser.class.getResourceAsStream(
                            resourceName);
            if (inputStream == null) {
                log.error("Resource "+resourceName+" not found, ignoring it.");
                continue;
            }
            InputSource insrc = new InputSource(inputStream);
           
            // Non-validating parse to DOM
            Document xsddom;
			try {
				xsddom = Parser.loadDom(insrc,false);
			} catch (Exception e) {
				log.error("Error parsing XML schema (" + resourceName + "): " + e);
				continue;
			}
            
            // Get the target namespace from the root element
            Element ele = xsddom.getDocumentElement();
            if (!ele.getLocalName().equals("schema")) {
                log.error("Schema file wrong root element:"+resourceName);
                continue;
            }
            String targetNamespace = ele.getAttribute("targetNamespace");
            if (targetNamespace==null) {
                log.error("Schema has no targetNamespace: "+resourceName);
                continue;
            }
            
            // Put the DOM in the Bucket keyed by namespace
            if (bucket.containsKey(targetNamespace)) {
                log.debug("Replacing XSD for namespace: "+targetNamespace+" "+filename);
            } else {
                log.debug("Defining XSD for namespace:  "+targetNamespace+" "+filename);
            }
            bucket.put(targetNamespace,xsddom);
        }
	}

}
