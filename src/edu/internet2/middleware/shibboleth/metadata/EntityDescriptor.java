/*
 * EntityDescriptor.java
 * 
 * Simplify the transition to SAML 2 by allowing the obsolete
 * "Provider" interface to be called by its new name "EntityDescriptor".
 * Can be used to add or rename fields while writing code that 
 * implements the new interface while continuing to support the old.
 */
package edu.internet2.middleware.shibboleth.metadata;

/**
 * @author Howard Gilbert
 */
public abstract class EntityDescriptor implements Provider {
    
    /**
     * Scan the array of Roles, return instance of a particular type
     * @param type  Sub-Class of ProviderRole
     * @return      instance of the type
     */
    public ProviderRole getRoleByType(Class type) {
        
        ProviderRole[] roles = this.getRoles();
        for (int i=0;i<roles.length;i++) {
            ProviderRole role = roles[i];
            if (type.isInstance(role))
                return role;
        }
         return null;
    }
    
    public 
    	AttributeAuthorityRole 
    getAttributeAuthorityRole(){
        AttributeAuthorityRole aa = (AttributeAuthorityRole) getRoleByType(AttributeAuthorityRole.class);
        return aa;
    }
	
    public 
    	IDPProviderRole 
    getHandleServer() {
        IDPProviderRole hs = (IDPProviderRole) getRoleByType(IDPProviderRole.class);
        return hs;
    }

    

}
