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

package edu.internet2.middleware.shibboleth.aap;

import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLException;

import edu.internet2.middleware.shibboleth.metadata.RoleDescriptor;

/**
 * Specifies handling of a specific SAML attribute
 * 
 * @author Scott Cantor
 */
public interface AttributeRule {

    /**
     *  Get the SAML name of the applicable attribute 
     *
     * @return The AttributeName
     */
    String getName();
    
    /**
     *  Get the SAML namespace of the applicable attribute 
     *
     * @return The AttributeNamespace
     */
    String getNamespace();
    
    /**
     *  Get the name of the class responsible for implementing this attribute 
     *
     * @return The factory class name
     */
    String getFactory();
    
    /**
     *  Get the shorthand name of the attribute 
     *
     * @return The shorthand name
     */
    String getAlias();
    
    /**
     *  Get the name of the protocol-specific header to export the attribute into 
     *
     * @return The header name
     */
    String getHeader();
    
    /**
     *  Is value matching of this attribute case-sensitive? 
     *
     * @return The case sensitivity of the values
     */
    boolean getCaseSensitive();
    
    /**
     *  Is the attribute formally scoped? 
     *
     * @return The scoped property
     */
    boolean getScoped();
    
    /**
     *  Applies a rule to an attribute, taking into account the role in
     *  which the issuer was acting
     *  
     * @param attribute The attribute to apply the filtering rule to
     * @param role  The metadata role in which the attribute issuer is acting
     * @throws SAMLException    Raised if the attribute is no longer valid after
     *  the filtering process (generally if all values are deleted)
     */
    void apply(SAMLAttribute attribute, RoleDescriptor role) throws SAMLException;
}
