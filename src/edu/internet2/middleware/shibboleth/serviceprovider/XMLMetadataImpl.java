/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * 
 * Process Shibboleth 1.2 Metadata and present an EntityDescriptor
 * interface.
 * 
 */
package edu.internet2.middleware.shibboleth.serviceprovider;

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
 * Wrap the metadata.provider.XMLMetadataProvider with a class that implements
 * the SP PluggableConfigurationComponent interface. Delegate all processing 
 * calls to the wrapped object.
 * 
 * <p>XMLMetadataProvider takes Node as a Constructor argument, but in the SP
 * a Pluggable has to be a Bean that can be created with a default constructor
 * and then be passed a Node to complete initialization.<p>
 */
class XMLMetadataImpl 
	implements 
		Metadata,
		PluggableConfigurationComponent
	{
    
    
	XMLMetadataProvider realObject = null;
	

	public void initialize(Node dom) 
		throws XmlException, ShibbolethConfigurationException {
	    try {
             realObject =
                new edu.internet2.middleware.shibboleth.metadata.provider.XMLMetadataProvider(
                        (dom instanceof Element) ? 
                                (Element)dom : 
                                ((dom instanceof Document) ? 
                                        ((Document)dom).getDocumentElement() : 
                                          null)
                    );
        }
        catch (SAMLException e) {
            throw new ShibbolethConfigurationException("Exception initializing metadata: " + e);
        }
	}
	
    public EntityDescriptor lookup(String id) {
        return realObject.lookup(id);
    }

    public EntityDescriptor lookup(Artifact artifact) {
        return realObject.lookup(artifact);
    }
}