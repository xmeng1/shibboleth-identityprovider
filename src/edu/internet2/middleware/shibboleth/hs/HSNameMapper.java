/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation
 * for Advanced Internet Development, Inc. All rights reserved
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
 * <http://www.ucaid.edu> Internet2 Project. Alternately, this acknowledegement
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
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package edu.internet2.middleware.shibboleth.hs;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.opensaml.SAMLNameIdentifier;

import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;
import edu.internet2.middleware.shibboleth.common.IdentityProvider;
import edu.internet2.middleware.shibboleth.common.InvalidNameIdentifierException;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMapping;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMappingException;
import edu.internet2.middleware.shibboleth.common.NameMapper;
import edu.internet2.middleware.shibboleth.common.ServiceProvider;

/**
 * <code>NameMapper</code> that additionally maps local <code>AuthNPrincipal</code>
 * to SAML Name Identifiers. Mappings can be associated with a <code>String</code>
 * id and recovered based on the same.
 * 
 * @author Walter Hoehn
 * @see NameMapper
 * @see HSNameIdentifierMapping
 */
public class HSNameMapper extends NameMapper {

	private Map byId = new HashMap();

	/**
	 * Adds a <code>NameIdentifierMapping</code> to this <code>HSNameMapper</code>,
	 * registering it according to its format and, if applicable, according to
	 * its id.
	 * 
	 * @param mapping
	 *            the mapping to add
	 */
	public void addNameMapping(NameIdentifierMapping mapping) {
		super.addNameMapping(mapping);
		if (mapping instanceof HSNameIdentifierMapping) {
			if (((HSNameIdentifierMapping) mapping).getId() != null
				&& (!((HSNameIdentifierMapping) mapping).getId().equals(""))) {
				byId.put(((HSNameIdentifierMapping) mapping).getId(), mapping);
			}
		}
	}

	/**
	 * Returns the <code>HSNameIdentifierMapping</code> registered for a
	 * given id
	 * 
	 * @param id
	 *            the registered id
	 * @return the mapping or <tt>null</tt> if no mapping is registered for
	 *         the given id
	 */
	public HSNameIdentifierMapping getNameIdentifierMappingById(String id) {

		if (id == null || id.equals("")) {
			if (!initialized) {
				return defaultMapping;
			}

			if (byFormat.size() == 1) {
				Iterator values = byFormat.values().iterator();
				Object mapping = values.next();
				if (mapping instanceof HSNameIdentifierMapping) {
					return (HSNameIdentifierMapping) mapping;
				}
			}
		}

		return (HSNameIdentifierMapping) byId.get(id);
	}

	/**
	 * 
	 * Maps a local principal to a SAML Name Identifier using the mapping registered under a given id.
	 * 
	 * @param id
	 *            the id under which the effective <code>HSNameIdentifierMapping</code>
	 *            is registered
	 * @param principal
	 *            the principal to map
	 * @param sProv
	 *            the provider initiating the request
	 * @param idProv
	 *            the provider handling the request
	 * @return @throws
	 *         NameIdentifierMappingException If the <code>NameMapper</code>
	 *         encounters an internal error
	 */
	public SAMLNameIdentifier getNameIdentifierName(
		String id,
		AuthNPrincipal principal,
		ServiceProvider sProv,
		IdentityProvider idProv)
		throws NameIdentifierMappingException {

		HSNameIdentifierMapping mapping = getNameIdentifierMappingById(id);

		if (mapping == null) {
			throw new InvalidNameIdentifierException("Name Identifier id not registered.");
		}
		return mapping.getNameIdentifierName(principal, sProv, idProv);
	}
}