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

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Stack;

import org.apache.log4j.Logger;
import org.apache.xmlbeans.XmlException;
import org.opensaml.SAMLAttributeDesignator;
import org.w3c.dom.Node;

import x0.maceShibboleth1.AuthorityType;
import x0.maceShibboleth1.ContactType;
import x0.maceShibboleth1.OriginSiteType;
import x0.maceShibboleth1.SiteGroupDocument;
import x0.maceShibboleth1.SiteGroupType;
import edu.internet2.middleware.shibboleth.common.XML;
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
class XMLMetadataImpl 
	implements 
		EntityLocator /* renamed "Metadata" interface */, 
		PluggableConfigurationComponent
	{
    
    private static Logger log = Logger.getLogger(XMLMetadataImpl.class);
    
	Map entityDescriptors = new HashMap();
	

	public void initialize(Node dom) 
		throws XmlException {
	    SiteGroupDocument bean = SiteGroupDocument.Factory.parse(dom);
		Stack parentgroups = new Stack();
		processGroup(bean.getSiteGroup(),parentgroups);
	}
	
	/**
	 * Drill down (recursively) through groups to wrap each
	 * OriginSite in a ProviderImp and index by Name.
	 * 
	 * @param group SiteGroup
	 */
	private void processGroup(SiteGroupType group, Stack parentgroups) {
		parentgroups.push(group.getName());
		Object[] parents = parentgroups.toArray();
		OriginSiteType[] sites = group.getOriginSiteArray();
		for (int i=0;i<sites.length;i++) {
			entityDescriptors.put(
			        sites[i].getName(),
			        new XMLEntityDescriptorImpl(sites[i],parents));
		}
		SiteGroupType[] subgroups = group.getSiteGroupArray();
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
     * OriginSite in the current Shibboleth configuration, and
     * for every EntityDescriptor in SAML 2 Metadata. It has 
     * a Role for the HS (IDP) and AA. Of course, it can also
     * be used in Origin code to describe Targets.
     */
    static private class XMLEntityDescriptorImpl extends EntityDescriptor {
    	
    	OriginSiteType site;  // The real XMLBean object
    	Object[] groups; // Actually array of SiteGroupTypes
    	ProviderRole[] roles = null;		
    	
    	XMLEntityDescriptorImpl(OriginSiteType site, Object [] groups) {
    		this.site=site;
    		this.groups=groups;
    		
    		ArrayList/*<ProviderRoles>*/ roleArray = new ArrayList();
    		
    		/*
    		 * Note: The schema allows for more than one AA or IDP.
    		 * This makes sense in SAML 2.0 where different versions of
    		 * the protocol can be supported by different URL endpoints.
    		 * It is not clear how it would really be used here. This
    		 * code goes through the motions of constructing more than
    		 * one AA or IDP Role object, but in practice the subsequent
    		 * code will only use the first such object it encounters.
    		 */
    		
    		AuthorityType[] attributeAuthorityArray = site.getAttributeAuthorityArray();
    		if (attributeAuthorityArray.length>0) {
    			AttributeAuthorityRole aarole = 
    				new AttributeAuthorityRoleImpl(this,attributeAuthorityArray[0]);
    			roleArray.add(aarole);
    		}
    		AuthorityType[] handleServiceArray = site.getHandleServiceArray();
    		if (handleServiceArray.length>0) {
    			IDPProviderRole idprole =
    				new IDPProviderRoleImpl(this,handleServiceArray[0]);
    			roleArray.add(idprole);
    		}
    		roles = new ProviderRole[roleArray.size()];
    		Iterator iterator = roleArray.iterator();
    		for (int i=0;i<roles.length;i++) {
    		    roles[i]= (ProviderRole) iterator.next();
    		}
    	}
    	
    	public String getId() {
    		return site.getName();
    	}
    	
    	public String[] getGroups() {
    		String [] groupnames = new String[groups.length];
    		for (int i=0;i<groups.length;i++) {
    			groupnames[i]=((OriginSiteType)groups[i]).getName();
    		}
    		return groupnames;
    	}
    
    	public ContactPerson[] getContacts() {
    		ContactType[] contacts = site.getContactArray();
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
    		return contact.getType().intValue();
    	}
    
    	public String getName() {
    		return contact.getName();
    	}
    
    	public String[] getEmails() {
    		return new String[] {contact.getEmail()};
    	}
    
    	public String[] getTelephones() {
    		return null;
    	}
    	
    }

    /**
     * implements ...metadata.ProviderRole and Endpoint for XML data
     * 
     * Note: In the Origin code, the ProviderRole is
     * implemented directly by the Provider object 
     * (because from the Origin the Provider has only
     * one Role). This is not a generally good idea
     * and it will not work if we move to SAML 2.0 
     * Metadata. So might as well clean it up now.
     */
    static private class XMLProviderRoleImpl 
    	implements ProviderRole, Endpoint {
    	
    	EntityDescriptor entity;
    	private String name;
    	private String location;
    	
    	XMLProviderRoleImpl(EntityDescriptor entity, AuthorityType a) {
    		this.entity=entity;
    		this.name = a.getName();
    		this.location = a.getLocation();
    	}
    
    	public Provider getProvider() {
    		return entity;
    	}
    
    	public String[] getProtocolSupport() {
    		return new String[]{XML.SHIB_NS};
    	}
    
    	public boolean hasSupport(String version) {
    		if (version.equals(XML.SHIB_NS)) {
    			return true;
    		} else {
    			return false;
    		}
    	}
    
    	public ContactPerson[] getContacts() {
    		return entity.getContacts();
    	}
    
    	public KeyDescriptor[] getKeyDescriptors() {
    		return null;
    	}
    
    	public Endpoint[] getDefaultEndpoints() {
    		return new Endpoint[] {this};
    	}
    
    	public URL getErrorURL() {
    		return null;
    	}
    
    	public String getBinding() {
    		return XML.SHIB_NS;
    	}
    
    	public String getVersion() {
    		return null;
    	}
    
    	public String getLocation() {
    		return location;
    	}
    
    	public String getResponseLocation() {
    		return null;
    	}
    }

    /**
     * implements ...metadata.Endpoint for XML data
     * 
     * <p>For now, the Endpoint just wraps a URL.</p>
     */
    static private class XMLEndpointImpl implements Endpoint {
    	
    	private String location;
    	
    	XMLEndpointImpl(String location) {
    		this.location=location;
    	}
    
    	public String getBinding() {
    		return XML.SHIB_NS;
    	}
    
    	public String getVersion() {
    		return null;
    	}
    
    	public String getLocation() {
    		return location;
    	}
    
    	public String getResponseLocation() {
    		return null;
    	}
    	
    }

    /**
     * A subtype of generic roles for AttributeAuthority entries.
     */
    private static class AttributeAuthorityRoleImpl
    	extends XMLProviderRoleImpl
    	implements AttributeAuthorityRole {
    
    	public AttributeAuthorityRoleImpl(EntityDescriptor entity, AuthorityType a) {
    		super(entity, a);
    	}
    
    	public Endpoint[] getAttributeServices() {
    		return new Endpoint[] {this};
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
    
        public IDPProviderRoleImpl(EntityDescriptor entity, AuthorityType a) {
            super(entity, a);
        }
    }

    /**
     * @return
     */
    public String getSchemaPathname() {
        return null;
    }
}