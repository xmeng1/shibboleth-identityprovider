/* 
 * The Shibboleth License, Version 1. 
 * Copyright (c) 2002 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
 * 
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this 
 * list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution, if any, must include 
 * the following acknowledgment: "This product includes software developed by 
 * the University Corporation for Advanced Internet Development 
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement 
 * may appear in the software itself, if and wherever such third-party 
 * acknowledgments normally appear.
 * 
 * Neither the name of Shibboleth nor the names of its contributors, nor 
 * Internet2, nor the University Corporation for Advanced Internet Development, 
 * Inc., nor UCAID may be used to endorse or promote products derived from this 
 * software without specific prior written permission. For written permission, 
 * please contact shibboleth@shibboleth.org
 * 
 * Products derived from this software may not be called Shibboleth, Internet2, 
 * UCAID, or the University Corporation for Advanced Internet Development, nor 
 * may Shibboleth appear in their name, without prior written permission of the 
 * University Corporation for Advanced Internet Development.
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK 
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY 
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.common;


/**
 *  Utility class for XML constants
 *
 * @author     Scott Cantor
 * @created    January 2, 2002
 */
public class XML
{
    /**  Shibboleth XML namespace */
    public final static String SHIB_NS = "urn:mace:shibboleth:1.0";
    
    /**  Shibboleth XML schema identifier */
    public final static String SHIB_SCHEMA_ID = "shibboleth.xsd";
    
    /**  Shibboleth Metadata XML namespace */
    public final static String SHIBMETA_NS = "urn:mace:shibboleth:1.0:metadata";
    
    /**  Shibboleth XML schema identifier */
    public final static String SHIBMETA_SCHEMA_ID = "shibboleth-metadata-1.0.xsd";

    /**  Shibboleth trust metadata XML namespace */
    public final static String TRUST_NS = "urn:mace:shibboleth:trust:1.0";
    
    /**  Shibboleth trust metadata XML schema identifier */
    public final static String TRUST_SCHEMA_ID = "shibboleth-trust-1.0.xsd";
    
    public final static String MAIN_SHEMA_ID = "shibboleth-targetconfig-1.0.xsd";
    public final static String ORIGIN_SHEMA_ID = "origin.xsd";
    
    public final static String XMLSIG_RETMETHOD_RAWX509    = "http://www.w3.org/2000/09/xmldsig#rawX509Certificate";
    public final static String XMLSIG_RETMETHOD_RAWX509CRL = "http://www.w3.org/2000/09/xmldsig-more#rawX509CRL";
    public final static String SHIB_RETMETHOD_PEMX509      = "urn:mace:shibboleth:RetrievalMethod:pemX509Certificate";
    public final static String SHIB_RETMETHOD_PEMX509CRL   = "urn:mace:shibboleth:RetrievalMethod:pemX509CRL";
    
}
