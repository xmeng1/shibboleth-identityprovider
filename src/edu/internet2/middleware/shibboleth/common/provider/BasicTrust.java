/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
 * provided with the distribution, if any, must include the following acknowledgment: "This product includes software
 * developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu> Internet2 Project.
 * Alternately, this acknowledegement may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear. Neither the name of Shibboleth nor the names of its contributors, nor Internet2, nor
 * the University Corporation for Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote
 * products derived from this software without specific prior written permission. For written permission, please contact
 * shibboleth@shibboleth.org Products derived from this software may not be called Shibboleth, Internet2, UCAID, or the
 * University Corporation for Advanced Internet Development, nor may Shibboleth appear in their name, without prior
 * written permission of the University Corporation for Advanced Internet Development. THIS SOFTWARE IS PROVIDED BY THE
 * COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE
 * DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. IN NO
 * EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC.
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.common.provider;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.keyresolver.KeyResolverException;
import org.opensaml.SAMLSignedObject;

import edu.internet2.middleware.shibboleth.common.Trust;
import edu.internet2.middleware.shibboleth.metadata.KeyDescriptor;
import edu.internet2.middleware.shibboleth.metadata.RoleDescriptor;

/**
 * <code>Trust</code> implementation that validates against standard inline keying data within SAML 2 metadata.
 * 
 * @author Walter Hoehn
 */
public class BasicTrust implements Trust {

	private static Logger log = Logger.getLogger(BasicTrust.class.getName());

	/*
	 * @see edu.internet2.middleware.shibboleth.common.Trust#validate(java.security.cert.X509Certificate,
     *  java.security.cert.X509Certificate[], edu.internet2.middleware.shibboleth.metadata.RoleDescriptor, boolean)
	 */
	public boolean validate(X509Certificate certificateEE, X509Certificate[] certificateChain, RoleDescriptor descriptor, boolean checkName) {

		if (descriptor == null || certificateEE == null) {
			log.error("Appropriate data was not supplied for trust evaluation.");
			return false;
		}

		// Iterator through all the keys in the metadata
		Iterator keyDescriptors = descriptor.getKeyDescriptors();
		while (keyDescriptors.hasNext()) {
			// Look for a key descriptor with the right usage bits
			KeyDescriptor keyDescriptor = (KeyDescriptor) keyDescriptors.next();
			if (keyDescriptor.getUse() == KeyDescriptor.ENCRYPTION) {
				log.debug("Skipping key descriptor with inappropriate usage indicator.");
				continue;
			}

			// We found one, attempt to do an exact match between the metadata certificate
			// and the supplied end-entity certificate
			KeyInfo keyInfo = keyDescriptor.getKeyInfo();
			if (keyInfo.containsX509Data()) {
				log.debug("Attempting to match X509 certificate.");
				try {
					X509Certificate metaCert = keyInfo.getX509Certificate();
					if (Arrays.equals(metaCert.getEncoded(), certificateEE.getEncoded())) {
						log.debug("Match successful.");
						return true;
					} else {
						log.debug("Certificate did not match.");
					}

				} catch (KeyResolverException e) {
					log.error("Error extracting X509 certificate from metadata.");
				} catch (CertificateEncodingException e) {
					log.error("Error while comparing X509 encoded data.");
				}
			}
		}
		return false;
	}

    /*
     * @see edu.internet2.middleware.shibboleth.common.Trust#validate(java.security.cert.X509Certificate, java.security.cert.X509Certificate[], edu.internet2.middleware.shibboleth.metadata.RoleDescriptor)
     */
    public boolean validate(X509Certificate certificateEE, X509Certificate[] certificateChain, RoleDescriptor descriptor) {
        return validate(certificateEE, certificateChain, descriptor, true);
    }

    /*
     * @see edu.internet2.middleware.shibboleth.common.Trust#validate(org.opensaml.SAMLSignedObject, edu.internet2.middleware.shibboleth.metadata.RoleDescriptor)
     */
    public boolean validate(SAMLSignedObject token, RoleDescriptor descriptor) {
        // TODO Auto-generated method stub
        
        /*
         * Proposed algorithm for this is just to walk each KeyDescriptor with keyUse of signing
         * and try and extract a public key to use and try and verify the token. If it works, we're
         * done.
         */ 
        return false;
    }
}