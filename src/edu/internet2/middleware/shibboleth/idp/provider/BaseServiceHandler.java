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

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolHandler;
import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;
import edu.internet2.middleware.shibboleth.metadata.KeyDescriptor;
import edu.internet2.middleware.shibboleth.metadata.SPSSODescriptor;

/**
 * @author Walter Hoehn
 */
public abstract class BaseServiceHandler extends BaseHandler implements IdPProtocolHandler {

	/**
	 * Required DOM-based constructor.
	 */
	public BaseServiceHandler(Element config) throws ShibbolethConfigurationException {

		super(config);
	}

	private static Logger log = Logger.getLogger(BaseServiceHandler.class.getName());

	protected static X509Certificate getCredentialFromProvider(HttpServletRequest req) {

		X509Certificate[] certArray = (X509Certificate[]) req.getAttribute("javax.servlet.request.X509Certificate");
		if (certArray != null && certArray.length > 0) { return certArray[0]; }
		return null;
	}

	protected static boolean isValidCredential(EntityDescriptor provider, X509Certificate certificate) {

		SPSSODescriptor sp = provider.getSPSSODescriptor(org.opensaml.XML.SAML11_PROTOCOL_ENUM);
		if (sp == null) {
			log.info("Inappropriate metadata for provider.");
			return false;
		}

		Iterator descriptors = sp.getKeyDescriptors();
		while (descriptors.hasNext()) {
			KeyInfo keyInfo = ((KeyDescriptor) descriptors.next()).getKeyInfo();
			for (int l = 0; keyInfo.lengthKeyName() > l; l++) {
				try {

					// First, try to match DN against metadata
					try {
						if (certificate.getSubjectX500Principal().getName(X500Principal.RFC2253).equals(
								new X500Principal(keyInfo.itemKeyName(l).getKeyName()).getName(X500Principal.RFC2253))) {
							log.debug("Matched against DN.");
							return true;
						}
					} catch (IllegalArgumentException iae) {
						// squelch this runtime exception, since
						// this might be a valid case
					}

					// If that doesn't work, we try matching against
					// some Subject Alt Names
					try {
						Collection altNames = certificate.getSubjectAlternativeNames();
						if (altNames != null) {
							for (Iterator nameIterator = altNames.iterator(); nameIterator.hasNext();) {
								List altName = (List) nameIterator.next();
								if (altName.get(0).equals(new Integer(2)) || altName.get(0).equals(new Integer(6))) {
									// 2 is DNS, 6 is URI
									if (altName.get(1).equals(keyInfo.itemKeyName(l).getKeyName())) {
										log.debug("Matched against SubjectAltName.");
										return true;
									}
								}
							}
						}
					} catch (CertificateParsingException e1) {
						log.error("Encountered an problem trying to extract Subject Alternate "
								+ "Name from supplied certificate: " + e1);
					}

					// If that doesn't work, try to match using
					// SSL-style hostname matching
					if (getHostNameFromDN(certificate.getSubjectX500Principal()).equals(
							keyInfo.itemKeyName(l).getKeyName())) {
						log.debug("Matched against hostname.");
						return true;
					}

				} catch (XMLSecurityException e) {
					log.error("Encountered an error reading federation metadata: " + e);
				}
			}
		}
		log.info("Supplied credential not found in metadata.");
		return false;
	}

	protected class InvalidProviderCredentialException extends Exception {

		public InvalidProviderCredentialException(String message) {

			super(message);
		}
	}
}