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

package edu.internet2.middleware.shibboleth.hs;

import java.io.*;
import java.util.*;
import java.security.*;
import java.security.cert.*;
import edu.internet2.middleware.shibboleth.*;
import edu.internet2.middleware.shibboleth.common.*;
import org.opensaml.*;

public class HandleServiceSAML {

    protected String domain;
    protected String AAurl;
    public String[] policies = { Constants.POLICY_CLUBSHIB };
    private ShibPOSTProfile spp;
    PrivateKey privateKey;
    java.security.cert.Certificate[] certs;

    public HandleServiceSAML( String domain, String AAurl, String HSname,
			      String KSpass, String KSkeyalias,
			      String KSkeypass, String certalias, 
			      InputStream is ) 
	throws SAMLException, KeyStoreException, IOException, Exception
    {
	this.domain = domain;
	this.AAurl = AAurl;
	
	KeyStore ks = KeyStore.getInstance("JKS");
	ks.load( is, KSpass.toCharArray());
	privateKey = (PrivateKey)ks.getKey(KSkeyalias, KSkeypass.toCharArray());
	certs = ks.getCertificateChain(certalias);
	
	spp = ShibPOSTProfileFactory.getInstance( Arrays.asList(policies), HSname );
    }
    
    public byte[] prepare ( String handle, String shireURL, 
    String clientAddress, String authMethod, Date authInstant ) 
	throws HandleException {

	try { 
	    SAMLAuthorityBinding binding =
            new SAMLAuthorityBinding(SAMLBinding.SAML_SOAP_HTTPS, AAurl, 
		                              new QName(org.opensaml.XML.SAMLP_NS,"AttributeQuery")
                                      );
	    SAMLResponse r = spp.prepare 
	    ( shireURL, handle, domain, clientAddress, authMethod, 
	      authInstant, Collections.singleton(binding), privateKey, Arrays.asList(certs), null, null
	      );
	    byte[] buf = r.toBase64();
	    
	    return buf;
	}
	catch (SAMLException ex) {
	    throw new HandleException( "Error creating SAML assertion: "+ex );
	}
	catch (IOException ex) {
	    throw new HandleException( "Error converting SAML assertion: "+ex);
	}
    }
}
				      
				
	      
			    

    
