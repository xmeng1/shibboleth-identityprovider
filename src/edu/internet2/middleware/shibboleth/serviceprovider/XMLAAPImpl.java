/*
 * XMLAAPImpl.java
 * 
 * Implement the AAP and AttributeRule interfaces using the XML Beans
 * generated from the <AttributeAcceptancePolicy> root element.
 * 
 * If an external AAP file is changed and reparsed, then a new instance
 * of this object must be created from the new XMLBean to replace the
 * previous object in the Config Map of AAP interface implementing 
 * objects key by its URI.
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

import java.util.Iterator;

import org.apache.log4j.Logger;
import org.opensaml.SAMLException;

import edu.internet2.middleware.shibboleth.aap.provider.XMLAAPProvider;
import edu.internet2.middleware.shibboleth.aap.AAP;
import edu.internet2.middleware.shibboleth.aap.AttributeRule;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * An XMLAAPImpl object implements the AAP interface by creating
 * and maintaining objects that implement the AttributeRule interface.
 * The real work is done in AttributeRule.apply() where a 
 * SAML Attribute Assertion is compared to policy and invalid values
 * or assertions are removed.
 * 
 * A new instance of this object should be created whenever the
 * AAP XML configuration file is changed and reparsed. The new object
 * should then replace the old object in the Map that ServiceProviderConfig
 * maintains keyed by file URI, holding implementors of the AAP interface.
 */
public class XMLAAPImpl 
	implements AAP,
	PluggableConfigurationComponent {
	
	private static Logger log = Logger.getLogger(XMLAAPImpl.class);
    XMLAAPProvider realObject = null;
	
    public void initialize(Node dom) throws ShibbolethConfigurationException {
        try {
            // Assuming this just gets a DOM tree containing the AAP,
            // hopefully this will "just work".
            realObject =
                new edu.internet2.middleware.shibboleth.aap.provider.XMLAAPProvider(
                        (dom instanceof Element) ? (Element)dom : ((dom instanceof Document) ? ((Document)dom).getDocumentElement() : null)
                    );
        }
        catch (SAMLException e) {
            throw new ShibbolethConfigurationException("Exception initializing AAP: " + e);
        }
    }
	
    public boolean anyAttribute() {
        return realObject.anyAttribute();
    }
	
	public AttributeRule lookup(String name, String namespace) {
        return realObject.lookup(name,namespace);
	}

	public AttributeRule lookup(String alias) {
		return realObject.lookup(alias);
	}

	public Iterator getAttributeRules() {
		return realObject.getAttributeRules();
	}
	
    public String getSchemaPathname() {
       return null;
    }
}
