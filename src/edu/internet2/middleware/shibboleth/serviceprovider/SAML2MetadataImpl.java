/*
 * SAML2MetadataImpl.java
 * 
 * Process SAML 2 Metadata and present an EntityDescriptor
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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Stack;

import org.apache.log4j.Logger;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xmlbeans.XmlException;
import org.opensaml.SAMLAttributeDesignator;
import org.w3.x2001.x04.xmlenc.EncryptionMethodType;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import x0Metadata.oasisNamesTcSAML2.AttributeAuthorityDescriptorType;
import x0Metadata.oasisNamesTcSAML2.ContactType;
import x0Metadata.oasisNamesTcSAML2.EndpointType;
import x0Metadata.oasisNamesTcSAML2.EntitiesDescriptorDocument;
import x0Metadata.oasisNamesTcSAML2.EntitiesDescriptorType;
import x0Metadata.oasisNamesTcSAML2.EntityDescriptorType;
import x0Metadata.oasisNamesTcSAML2.IDPSSODescriptorType;
import x0Metadata.oasisNamesTcSAML2.KeyDescriptorType;
import x0Metadata.oasisNamesTcSAML2.RoleDescriptorType;
import edu.internet2.middleware.shibboleth.metadata.AttributeAuthorityRole;
import edu.internet2.middleware.shibboleth.metadata.ContactPerson;
import edu.internet2.middleware.shibboleth.metadata.Endpoint;
import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;
import edu.internet2.middleware.shibboleth.metadata.EntityLocator;
import edu.internet2.middleware.shibboleth.metadata.IDPProviderRole;
import edu.internet2.middleware.shibboleth.metadata.KeyDescriptor;
import edu.internet2.middleware.shibboleth.metadata.Provider;
import edu.internet2.middleware.shibboleth.metadata.ProviderRole;


/**
 * Shibboleth 1.2 XML Metadata support
 */
class SAML2MetadataImpl 
	implements 
		EntityLocator /* renamed "Metadata" interface */, 
		PluggableConfigurationComponent
	{
    
    private static Logger log = Logger.getLogger(SAML2MetadataImpl.class);
    
	Map entityDescriptors = new HashMap();
	

	public void initialize(Node dom) 
		throws XmlException {
	    EntitiesDescriptorDocument bean=null;
        bean = EntitiesDescriptorDocument.Factory.parse(dom);
        Stack parentgroups = new Stack();
		processGroup(bean.getEntitiesDescriptor(),parentgroups);
	}
	
	public String getSchemaPathname() {
	    return "/schemas/sstc-saml-schema-metadata-2.0.xsd";
	}
	
	/**
	 * Drill down (recursively) through groups to wrap each
	 * OriginSite in a ProviderImp and index by Name.
	 * 
	 * @param group SiteGroup
	 */
	private void processGroup(
	        EntitiesDescriptorType group, 
	        Stack /*<EntitiesDescriptorType>*/ parentgroups) {
		parentgroups.push(group);
		EntitiesDescriptorType[] parents = 
		    new EntitiesDescriptorType[parentgroups.size()];
		Iterator/*<EntitiesDescriptorType>*/ iterator = parentgroups.iterator();
		for (int i=0;i<parentgroups.size();i++) {
		    parents[i]=(EntitiesDescriptorType)iterator.next();
		}
		EntityDescriptorType[] sites = group.getEntityDescriptorArray();
		for (int i=0;i<sites.length;i++) {
			entityDescriptors.put(
			        sites[i].getEntityID(),
			        new XMLEntityDescriptorImpl(sites[i],parents));
		}
		EntitiesDescriptorType[] subgroups = group.getEntitiesDescriptorArray();
		for (int i=0;i<subgroups.length;i++) {
			processGroup(subgroups[i],parentgroups);
		}
		parentgroups.pop();
	}

	/**
	 * implement ...metadata.Metadata.lookup
	 * @param entityId ID of remote site
	 * @return EntityDescriptor cast as Provider to fulfill interface
	 */
	public Provider lookup(String entityId) {
		return (EntityDescriptor) entityDescriptors.get(entityId);
	}
	
	/**
	 * SAML 2 rename of lookup
	 * @param entityId ID of remote site
	 * @return EntityDescriptor of site
	 */
	public EntityDescriptor getEntityDescriptor(String entityId) {
		return (EntityDescriptor) entityDescriptors.get(entityId);
	}

    /**
     * implements ...metadata.Provider for XML data
     * 
     * <p>An object of this class is constructed for every 
     * EntityDescriptor (site) in SAML 2 Metadata.
     */
    static private class XMLEntityDescriptorImpl extends EntityDescriptor {
    	
    	private EntityDescriptorType site;  // The XMLBean object
    	
    	private EntitiesDescriptorType[] groups; // ancestor elements
    	
    	private ProviderRole[] roles = null; // child roles		
    	
    	XMLEntityDescriptorImpl(
    	        EntityDescriptorType site, 
    	        EntitiesDescriptorType[] groups) {
    		this.site=site;
    		this.groups=groups;
    		
    		ArrayList/*<ProviderRoles>*/ roleArray = 
    		    new ArrayList/*<ProviderRoles>*/();
    		
    		/*
    		 * The rolesArray combines objects constructed from 
    		 * different types of roles. However, the implementing
    		 * objects must be constructed from the specific subtypes
    		 */
    		
    		AttributeAuthorityDescriptorType[] attributeAuthorityArray = 
    		    site.getAttributeAuthorityDescriptorArray();
    		for (int i=0;i<attributeAuthorityArray.length;i++) {
    			AttributeAuthorityRole aarole = 
    				new AttributeAuthorityRoleImpl(this,attributeAuthorityArray[i]);
    			roleArray.add(aarole);
    		}
    		
    		IDPSSODescriptorType[] handleServiceArray = site.getIDPSSODescriptorArray();
    		for (int i=0;i<attributeAuthorityArray.length;i++) {
    			IDPProviderRole idprole =
    				new IDPProviderRoleImpl(this,handleServiceArray[i]);
    			roleArray.add(idprole);
    		}
    		
    		// Put code to process more specific roles here as they are
    		// needed by Shibboleth
    		
    		roles = new ProviderRole[roleArray.size()];
    		Iterator iterator = roleArray.iterator();
    		for (int i=0;i<roles.length;i++) {
    		    roles[i]= (ProviderRole) iterator.next();
    		}
    	}
    	
    	public String getId() {
    		return site.getEntityID();
    	}
    	
    	public String[] getGroups() {
    		String [] groupnames = new String[groups.length];
    		for (int i=0;i<groups.length;i++) {
    			groupnames[i]=(groups[i]).getName();
    		}
    		return groupnames;
    	}
    
    	public ContactPerson[] getContacts() {
    	    // Create the interface objects on demand
    		ContactType[] contacts = site.getContactPersonArray();
    		XMLContactPersonImpl[] retarray = new XMLContactPersonImpl[contacts.length];
    		for (int i=0;i<contacts.length;i++) {
    			retarray[i]=new XMLContactPersonImpl(contacts[i]);
    		}
    		return retarray;
    	}
    
    	public ProviderRole[] getRoles() {
    		return roles;
    	}
    }

    /**
     * implements ...metadata.ContactPerson for XML data
     */
    static private class XMLContactPersonImpl implements ContactPerson {
    	
        ContactType contact; // Wrapped XMLBean object
    	
    	XMLContactPersonImpl(ContactType contact) {
    		this.contact=contact;
    	}
    
    	/*
    	 * Dependency: the order of values in the XSD enumeration
    	 * must match the order of values defined in the interface.
    	 * [If someone objects, we can go back and get the string
    	 * matching elseif logic.]
    	 */
    	public int getType() {
    		return contact.getContactType().intValue();
    	}
    
    	public String getName() {
    		return contact.getGivenName()+" "+contact.getSurName();
    	}
    
    	public String[] getEmails() {
    		return contact.getEmailAddressArray();
    	}
    
    	public String[] getTelephones() {
    		return contact.getTelephoneNumberArray();
    	}
    	
    }

    /**
     * implements ...metadata.ProviderRole
     * 
     * <p>Represents a RoleDescriptor or (more commonly) one of its
     * explicitly defined subtypes IDPSSO, SPSSO, AuthnAuthority, 
     * PDP, AA, or AttributeConsumer).</p>
     * 
     * <p>We would make this class abstract, except that in theory
     * somewhere down the line we may want to support the RoleDescriptor
     * SAML 2 Metadata tag that allows new roles to be defined beyond
     * the roles explicitly mentioned in the standard. Should that 
     * occur, then the constructor for this class should become
     * public. Now it is protected so you can only instantiate
     * subclasses, but cannot create an object of this class directly.</p>
     */
    static private class XMLProviderRoleImpl 
    	implements ProviderRole {
    	
        RoleDescriptorType roleDescriptorType = null;
        
    	EntityDescriptor entity; // parent Entity
    	
    	private String name;
    	
    	Endpoint[] endpoints = null;
    	
    	String[] protocolUris = null;
    	
    	KeyDescriptor[] keyDescriptors= null;

    	protected XMLProviderRoleImpl(
    	        EntityDescriptor entity,
    	        RoleDescriptorType role) {
    		this.entity=entity;
    		this.roleDescriptorType = role;

    	    List protocolSupportEnumeration = 
    	        roleDescriptorType.getProtocolSupportEnumeration();
    	    protocolUris = new String[protocolSupportEnumeration.size()];
    	    Iterator iterator = protocolSupportEnumeration.iterator();
    	    for (int i=0;i<protocolUris.length;i++) {
    	        protocolUris[i]=(String) iterator.next();
    	    }
    	    
    	    KeyDescriptorType[] keyDescriptorArray = 
    	        roleDescriptorType.getKeyDescriptorArray();
    	    
    		keyDescriptors = new KeyDescriptor[keyDescriptorArray.length];
    		for (int i=0;i<keyDescriptorArray.length;i++) {
    		    keyDescriptors[i]= new KeyDescriptorImpl(keyDescriptorArray[i]); 
    		}
    		
    		
    		// The Endpoints types are specific to the subtypes
    		// So the Endpoint array must be filled in by the
    		// constructor of subclasses.
  	}
    
    	public Provider getProvider() {
    		return entity;
    	}
    
    	public String[] getProtocolSupport() {
    		return protocolUris;
    	}
    
    	public boolean hasSupport(String version) {
    	    return roleDescriptorType.getProtocolSupportEnumeration().contains(version);
    	}
    
    	public ContactPerson[] getContacts() {
    	    // Maybe we should return the contacts for the role???
    		return entity.getContacts();
    	}
    
    	public KeyDescriptor[] getKeyDescriptors() {
    		return keyDescriptors;
    	}
    
    	public Endpoint[] getDefaultEndpoints() {
    		return endpoints;
    	}
    
    	public URL getErrorURL() {
    		try {
                return new URL(roleDescriptorType.getErrorURL());
            } catch (MalformedURLException e) {
                return null;
           }
    	}
    
    }

    /**
     * implements ...metadata.Endpoint for XML data
     * 
     * <p>Delegate calls to the XMLBean EndpointType</p>
     */
    static private class XMLEndpointImpl implements Endpoint {
        
    	EndpointType endpoint;
    	
    	XMLEndpointImpl(EndpointType xmlbean) {
    	    this.endpoint=xmlbean;
    	}
    
    	public String getBinding() {
    		return endpoint.getBinding();
    	}
    
    	public String getLocation() {
    		return endpoint.getLocation();
    	}
    
    	public String getResponseLocation() {
    		return endpoint.getResponseLocation();
    	}
    	
    }

    /**
     * A subtype of generic roles for AttributeAuthority entries.
     */
    private static class AttributeAuthorityRoleImpl
    	extends XMLProviderRoleImpl
    	implements AttributeAuthorityRole {
    
        // Yes, this is redundant with the parent class reference 
        // to the same object as a generic RoleDescriptorType, but
        // having a more specific field saves casting that field
        // all the time in this code.
        AttributeAuthorityDescriptorType aabean;
    
        public AttributeAuthorityRoleImpl(
                XMLEntityDescriptorImpl impl, 
                AttributeAuthorityDescriptorType aaDescriptor) {
            
            super(impl,aaDescriptor);
            aabean=aaDescriptor;
            
            EndpointType[] attributeServiceArray = 
                aaDescriptor.getAttributeServiceArray();
            endpoints = new Endpoint[attributeServiceArray.length];
            for (int i=0;i<attributeServiceArray.length;i++) {
                endpoints[i]=new XMLEndpointImpl(attributeServiceArray[i]);
            }
        }

        public Endpoint[] getAttributeServices() {
    		return endpoints;
    	}
    
    	public SAMLAttributeDesignator[] getAttributeDesignators() {
    		return null;
    	}
    }

    /**
     * A subtype of generic roles for Handle Server entries.
     */
    private static class IDPProviderRoleImpl
    	extends XMLProviderRoleImpl
    	implements IDPProviderRole {
    
        IDPSSODescriptorType hsRole;
        
        public IDPProviderRoleImpl(XMLEntityDescriptorImpl impl, 
                IDPSSODescriptorType type) {
            super(impl,type);
            hsRole = type;
            
            EndpointType[] singleSignOnServiceArray = 
                type.getSingleSignOnServiceArray();
            endpoints = new Endpoint[singleSignOnServiceArray.length];
            for (int i=0;i<singleSignOnServiceArray.length;i++) {
                endpoints[i]=new XMLEndpointImpl(singleSignOnServiceArray[i]);
            }
        }
    }
    
    private static class KeyDescriptorImpl 
    	implements KeyDescriptor {
        
        KeyDescriptorType keyDescriptor = null;
        
        public KeyDescriptorImpl(KeyDescriptorType keyDescriptor) {
            super();
            this.keyDescriptor = keyDescriptor;
        }
        
        public String[] getEncryptionMethod() {
            EncryptionMethodType[] encryptionMethodArray = 
                keyDescriptor.getEncryptionMethodArray();
            String[] methods = new String[encryptionMethodArray.length];
            for (int i=0;i<encryptionMethodArray.length;i++) {
	            EncryptionMethodType encryptionMethod = encryptionMethodArray[i];
	            methods[i] =encryptionMethod.getAlgorithm();
            }
            return methods;
        }
        public KeyInfo[] getKeyInfo() {
            Node fragment = keyDescriptor.getKeyInfo().newDomNode();
            Element node = (Element) fragment.getFirstChild();
            KeyInfo info = null;
            try {
                info = new KeyInfo(node,"");
            } catch (XMLSecurityException e) {
                return null;
            }
            return new KeyInfo[] {info};
        }
        
        public int getUse() {
            String value = keyDescriptor.getUse().toString();
            if (value.equals("encryption"))
                return KeyDescriptor.ENCRYPTION;
            else
                return KeyDescriptor.SIGNING;
        }
}
}