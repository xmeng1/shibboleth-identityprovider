/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the
 * above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution, if any, must include the following acknowledgment: "This product includes
 * software developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu>Internet2
 * Project. Alternately, this acknowledegement may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear. Neither the name of Shibboleth nor the names of its contributors, nor Internet2,
 * nor the University Corporation for Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote
 * products derived from this software without specific prior written permission. For written permission, please
 * contact shibboleth@shibboleth.org Products derived from this software may not be called Shibboleth, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor may Shibboleth appear in their name,
 * without prior written permission of the University Corporation for Advanced Internet Development. THIS SOFTWARE IS
 * PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND
 * NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS
 * WITH LICENSEE. IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY CORPORATION FOR ADVANCED
 * INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.metadata;

import java.util.Iterator;
import java.util.Map;

import org.w3c.dom.Element;

/**
 * <p>Corresponds to SAML Metadata Schema "EntityDescriptorType".
 * </p><p>
 * Entities are campuses or departments with either an origin or target
 * infrastructure (or both). Each implemented component (HS, AA, SHAR) 
 * has a Role definition with URLs and PKI to locate and authenticate
 * the provider of that role. Although the Metadata may define all 
 * roles, target code tends to build objects describing origins, and 
 * origins are only interested in targets.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public interface EntityDescriptor {

	public String getId();  // Unique ID used as global key of Provider
    
    public boolean isValid();   // Is this entity descriptor "active"?

    public Iterator /* <RoleDescriptor> */ getRoleDescriptors(); // Role definitions

    /**
     *  Finds a role descriptor of a particular type that supports the
     *  specified protocol.
     * 
     * @param type  The type of role to locate
     * @param protocol  The protocol constant that must be supported
     * @return  The matching role decsriptor, if any
     */
    public RoleDescriptor getRoleByType(Class type, String protocol);
    
    public IDPSSODescriptor getIDPSSODescriptor(String protocol);
    public SPSSODescriptor getSPSSODescriptor(String protocol);
    public AuthnAuthorityDescriptor getAuthnAuthorityDescriptor(String protocol);
    public AttributeAuthorityDescriptor getAttributeAuthorityDescriptor(String protocol);
    public PDPDescriptor getPDPDescriptor(String protocol);
    public AffiliationDescriptor getAffiliationDescriptor();
    
    public Organization getOrganization();  // associated organization
    
    public Iterator /* <ContactPerson> */ getContactPersons();    // support contacts
    
    public Map /* <String,String> */ getAdditionalMetadataLocations(); // XML Namespace - location pairs
    
    public EntitiesDescriptor getEntitiesDescriptor(); // parent group, if any
    
    public Element getElement();    // punch through to raw XML, if enabled
}
