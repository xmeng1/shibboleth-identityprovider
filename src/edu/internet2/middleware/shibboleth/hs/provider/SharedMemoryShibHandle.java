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
package edu.internet2.middleware.shibboleth.hs.provider;

import org.apache.log4j.Logger;
import org.doomdark.uuid.UUIDGenerator;
import org.opensaml.SAMLNameIdentifier;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;
import edu.internet2.middleware.shibboleth.common.BaseNameIdentifierMapping;
import edu.internet2.middleware.shibboleth.common.IdentityProvider;
import edu.internet2.middleware.shibboleth.common.InvalidNameIdentifierException;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMappingException;
import edu.internet2.middleware.shibboleth.common.ServiceProvider;
import edu.internet2.middleware.shibboleth.hs.HSNameIdentifierMapping;

/**
 * @author Walter Hoehn
 */
public class SharedMemoryShibHandle extends BaseNameIdentifierMapping implements HSNameIdentifierMapping {
//TODO need to move the guts of this class out of the HandleRepository implementations
	private String id;
	protected HandleCache cache = HandleCache.instance();
	private static Logger log = Logger.getLogger(SharedMemoryShibHandle.class.getName());

	public SharedMemoryShibHandle(Element config) throws NameIdentifierMappingException {
		super(config);
		String id = ((Element) config).getAttribute("id");
		if (id != null || !id.equals("")) {
			this.id = id;
		}
	}

	public String getId() {
		return id;
	}

	public SAMLNameIdentifier getNameIdentifierName(
		AuthNPrincipal principal,
		ServiceProvider sProv,
		IdentityProvider idProv)
		throws NameIdentifierMappingException {

		if (principal == null) {
			log.error("A principal must be supplied for Attribute Query Handle creation.");
			throw new IllegalArgumentException("A principal must be supplied for Attribute Query Handle creation.");
		}

		String handle = UUIDGenerator.getInstance().generateRandomBasedUUID().toString();
		log.debug("Assigning handle (" + handle + ") to principal (" + principal.getName() + ").");
		synchronized (cache.handleEntries) {
			cache.handleEntries.put(handle, createHandleEntry(principal));
		}
		
		return new SAMLNameIdentifier(handle, "qualifier", getNameIdentifierFormat().toString());

	}

	public AuthNPrincipal getPrincipal(SAMLNameIdentifier nameId, ServiceProvider sProv, IdentityProvider idProv)
		throws NameIdentifierMappingException, InvalidNameIdentifierException {

		synchronized (cache.handleEntries) {
			if (!cache.handleEntries.containsKey(nameId.getName())) {
				log.debug("The Name Mapping Cache does not contain an entry for this Attribute Query Handle.");
				throw new InvalidNameIdentifierException("The Name Mapping Cache does not contain an entry for this Attribute Query Handle.");
			}
		}

		HandleEntry handleEntry;
		synchronized (cache.handleEntries) {
			handleEntry = (HandleEntry) cache.handleEntries.get(nameId.getName());
		}

		if (handleEntry.isExpired()) {
			log.debug("Attribute Query Handle is expired.");
			synchronized (cache.handleEntries) {
				cache.handleEntries.remove(nameId.getName());
			}
			throw new InvalidNameIdentifierException("Attribute Query Handle is expired.");
		} else {
			log.debug("Attribute Query Handle recognized.");
			return handleEntry.principal;
		}
	}


}
