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

package edu.internet2.middleware.shibboleth.hs.provider;

import java.util.Properties;

import org.apache.log4j.Logger;

import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;
import edu.internet2.middleware.shibboleth.common.Constants;
import edu.internet2.middleware.shibboleth.hs.HandleRepository;
import edu.internet2.middleware.shibboleth.hs.HandleRepositoryException;
import edu.internet2.middleware.shibboleth.hs.HandleRepositoryFactory;
import edu.internet2.middleware.shibboleth.hs.InvalidHandleException;

/**
 * <code>HandleRepository</code> implementation that uses principal names as handles
 * 
 * @author Scott Cantor (cantor.2@osu.edu)
 */
public class IdentityHandleRepository extends BaseHandleRepository implements HandleRepository {

	private static Logger log = Logger.getLogger(IdentityHandleRepository.class.getName());
    
    private String format = null;
    private HandleRepository generator = null;

	public IdentityHandleRepository(Properties properties) throws HandleRepositoryException {
		super(properties);
        format = properties.getProperty(
            "edu.internet2.middleware.shibboleth.hs.IdentityHandleRepository.formatURI",
            Constants.SHIB_NAMEID_FORMAT_URI
            );
        String className = properties.getProperty(
            "edu.internet2.middleware.shibboleth.hs.IdentityHandleRepository.handleGenerator",
            null
            );
        if (className != null) {
            generator = HandleRepositoryFactory.getInstance(className, properties);
            log.debug("Handle generation will be implemented by (" + className +  ")");
        }
        log.debug("Attribute Query Handle TTL set to (" + handleTTL + ") milliseconds.");
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.hs.HandleRepository#getHandle(Principal)
	 */
	public String getHandle(AuthNPrincipal principal, StringBuffer format) throws HandleRepositoryException {
        //Delegate handle creation?
        if (generator != null) {
            return generator.getHandle(principal, format);
        }
        
		if (principal == null || format == null) {
			log.error("A principal and format buffer must be supplied for Attribute Query Handle creation.");
			throw new IllegalArgumentException("A principal and format buffer must be supplied for Attribute Query Handle creation.");
		}

        format.setLength(0);
        format.append(this.format);

		return principal.getName();
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.hs.HandleRepository#getPrincipal(String)
	 */
	public AuthNPrincipal getPrincipal(String handle, String format) throws HandleRepositoryException, InvalidHandleException {
        if (format != null && format.equals(Constants.SHIB_NAMEID_FORMAT_URI)) {
            return generator.getPrincipal(handle, format);
        }
        
        return new AuthNPrincipal(handle);
	}
}
