/*
 * XMLMetadataImpl.java
 * 
 * Process Shibboleth 1.2 Metadata and present an EntityDescriptor
 * interface.
 * 
 * --------------------
 * Copyright 2002, 2004 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
 * [Thats all we have to say to protect ourselves]
 * Your permission to use this code is governed by "The Shibboleth License".
 * A copy may be found at http://shibboleth.internet2.edu/license.html
 * [Nothing in copyright law requires license text in every file.]
  */
package edu.internet2.middleware.shibboleth.serviceprovider;

import org.apache.log4j.Logger;
import org.apache.xmlbeans.XmlException;
import org.opensaml.SAMLException;
import org.opensaml.artifact.Artifact;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;
import edu.internet2.middleware.shibboleth.metadata.Metadata;
import edu.internet2.middleware.shibboleth.metadata.provider.XMLMetadataProvider;


/**
 * Shibboleth 1.2 XML Metadata support
 * 
 * TODO: This needs to be ripped out, but for now, I'll try and
 * just wrap the real metadata plugin with this thing.
 */
class XMLMetadataImpl 
	implements 
		Metadata,
		PluggableConfigurationComponent
	{
    
    private static Logger log = Logger.getLogger(XMLMetadataImpl.class);
    
	XMLMetadataProvider realObject = null;
	

	public void initialize(Node dom) 
		throws XmlException, ShibbolethConfigurationException {
	    try {
            // Assuming this just gets a DOM tree containing the metadata,
            // hopefully this will "just work".
            realObject =
                new edu.internet2.middleware.shibboleth.metadata.provider.XMLMetadataProvider(
                        (dom instanceof Element) ? (Element)dom : ((dom instanceof Document) ? ((Document)dom).getDocumentElement() : null)
                    );
        }
        catch (SAMLException e) {
            throw new ShibbolethConfigurationException("Exception initializing metadata: " + e);
        }
	}
	
    public String getSchemaPathname() {
        return null;
    }

    public EntityDescriptor lookup(String id) {
        return realObject.lookup(id);
    }

    public EntityDescriptor lookup(Artifact artifact) {
        return realObject.lookup(artifact);
    }
}