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

package edu.internet2.middleware.shibboleth.idp.provider;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Iterator;

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.LocalPrincipal;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMapping;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMappingException;
import edu.internet2.middleware.shibboleth.common.NameMapper;
import edu.internet2.middleware.shibboleth.common.RelyingParty;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolHandler;
import edu.internet2.middleware.shibboleth.idp.InvalidClientDataException;
import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;
import edu.internet2.middleware.shibboleth.metadata.SPSSODescriptor;

/**
 * @author Walter Hoehn
 */
public abstract class SSOHandler extends BaseHandler implements IdPProtocolHandler {

	private static Logger log = Logger.getLogger(BaseHandler.class.getName());

	/**
	 * Required DOM-based constructor.
	 */
	public SSOHandler(Element config) throws ShibbolethConfigurationException {

		super(config);

	}

	public static void validateEngineData(HttpServletRequest req) throws InvalidClientDataException {

		if ((req.getRemoteAddr() == null) || (req.getRemoteAddr().equals(""))) { throw new InvalidClientDataException(
				"Unable to obtain client address."); }
	}

	protected Date getAuthNTime(HttpServletRequest request) throws SAMLException {

		// Determine, if possible, when the authentication actually happened
		String suppliedAuthNInstant = request.getHeader("SAMLAuthenticationInstant");
		if (suppliedAuthNInstant != null && !suppliedAuthNInstant.equals("")) {
			try {
				return new SimpleDateFormat().parse(suppliedAuthNInstant);
			} catch (ParseException e) {
				log.error("An error was encountered while receiving authentication "
						+ "instant from authentication mechanism: " + e);
				throw new SAMLException(SAMLException.RESPONDER, "General error processing request.");
			}
		} else {
			return new Date(System.currentTimeMillis());
		}
	}

	/**
	 * Constructs a SAML Name Identifier of a given principal that is most appropriate to the relying party.
	 * 
	 * @param mapper
	 *            name mapping facility
	 * @param principal
	 *            the principal represented by the name identifier
	 * @param relyingParty
	 *            the party that will consume the name identifier
	 * @param descriptor
	 *            metadata descriptor for the party that will consume the name identifier
	 * @return the SAML Name identifier
	 * @throws NameIdentifierMappingException
	 *             if a name identifier could not be created
	 */
	protected SAMLNameIdentifier getNameIdentifier(NameMapper mapper, LocalPrincipal principal,
			RelyingParty relyingParty, EntityDescriptor descriptor) throws NameIdentifierMappingException {

		String[] availableMappings = relyingParty.getNameMapperIds();

		SPSSODescriptor role = descriptor.getSPSSODescriptor("urn:oasis:names:tc:SAML:1.1:protocol");

		// If we have preferred Name Identifier formats from the metadata, see if the we can find one that is configured
		// for this relying party
		if (role != null) {
			Iterator spPreferredFormats = role.getNameIDFormats();
			while (spPreferredFormats.hasNext()) {

				String preferredFormat = (String) spPreferredFormats.next();
				for (int i = 0; availableMappings != null && i < availableMappings.length; i++) {
					NameIdentifierMapping mapping = mapper.getNameIdentifierMappingById(availableMappings[i]);
					if (mapping != null && preferredFormat.equals(mapping.getNameIdentifierFormat().toString())) {
						log.debug("Found a supported name identifier format that "
								+ "matches the metadata for the relying party: ("
								+ mapping.getNameIdentifierFormat().toString() + ").");
						return mapping.getNameIdentifier(principal, relyingParty, relyingParty.getIdentityProvider());
					}
				}
			}
		}

		// If we didn't find any matches, then just use the default for the relying party
		String defaultNameMapping = null;
		if (availableMappings != null && availableMappings.length > 0) {
			defaultNameMapping = availableMappings[0];
		}
		SAMLNameIdentifier nameId = mapper.getNameIdentifier(defaultNameMapping, principal, relyingParty, relyingParty
				.getIdentityProvider());
		log.debug("Using the default name identifier format for this relying party: (" + nameId.getFormat());
		return nameId;
	}
}