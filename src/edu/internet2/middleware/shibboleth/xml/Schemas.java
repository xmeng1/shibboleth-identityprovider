/*
 * Schemas.java
 * 
 * For now there is only one implementation of Schema store -
 * a resource directory in the WAR file of the application.
 * So there is only one current implementation of this interface,
 * the SchemasDirectoryImpl class. But we define the interface
 * and later on there may be other schema-store options.
 */
package edu.internet2.middleware.shibboleth.xml;

import javax.xml.validation.Schema;

/**
 * @author Howard Gilbert
 */
public interface Schemas {
    
    Schema compileSchema(String[] namespaces);

}
