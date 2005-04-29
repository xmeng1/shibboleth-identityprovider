/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
 * provided with the distribution, if any, must include the following acknowledgment: "This product includes software
 * developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu>Internet2 Project.
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

package edu.internet2.middleware.shibboleth.aa.attrresolv.provider;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Iterator;

import javax.crypto.SecretKey;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver;
import edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugInException;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttribute;
import edu.internet2.middleware.shibboleth.common.ShibResource;

/**
 * <code>PersistentIDAttributeDefinition</code> implementation. Provides a persistent, but pseudonymous, identifier
 * for principals by hashing the principal name, requester, and a fixed secret salt.
 * 
 * @author Scott Cantor (cantor.2@osu.edu)
 */
public class PersistentIDAttributeDefinition extends BaseAttributeDefinition implements AttributeDefinitionPlugIn {

	private static Logger log = Logger.getLogger(PersistentIDAttributeDefinition.class.getName());
	protected byte salt[];
	protected String localPersistentId = null;
	protected String scope;

	/**
	 * Constructor for PersistentIDAttributeDefinition. Creates a PlugIn based on configuration information presented in
	 * a DOM Element.
	 */
	public PersistentIDAttributeDefinition(Element e) throws ResolutionPlugInException {

		super(e);
		localPersistentId = e.getAttributeNS(null, "sourceName");

		// Make sure we understand how to resolve the local persistent ID for the principal.
		if (localPersistentId != null && localPersistentId.length() > 0) {
			if (connectorDependencyIds.size() != 1 || !attributeDependencyIds.isEmpty()) {
				log.error("Can't specify the sourceName attribute without a single connector dependency.");
				throw new ResolutionPlugInException("Failed to initialize Attribute Definition PlugIn.");
			}
		} else if (!connectorDependencyIds.isEmpty()) {
			log.error("Can't specify a connector dependency without supplying the sourceName attribute.");
			throw new ResolutionPlugInException("Failed to initialize Attribute Definition PlugIn.");
		} else if (attributeDependencyIds.size() > 1) {
			log.error("Can't specify more than one attribute dependency, this is ambiguous.");
			throw new ResolutionPlugInException("Failed to initialize Attribute Definition PlugIn.");
		}

		// Grab user specified scope
		scope = e.getAttribute("scope");
		if (scope == null || scope.equals("")) {
			log.error("Attribute \"scope\" required to configure plugin.");
			throw new ResolutionPlugInException("Failed to initialize Attribute Definition PlugIn.");
		}

		// Salt can be either embedded in the element or pulled out of a keystore.
		NodeList salts = e.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "Salt");
		if (salts == null || salts.getLength() != 1) {
			log.error("Missing <Salt> from attribute definition configuration.");
			throw new ResolutionPlugInException("Failed to initialize Attribute Definition PlugIn.");
		}

		Element salt = (Element) salts.item(0);
		Node child = salt.getFirstChild();
		if (child != null && child.getNodeType() == Node.TEXT_NODE && child.getNodeValue() != null
				&& child.getNodeValue().length() >= 16) this.salt = child.getNodeValue().getBytes();
		else {
			String ksPath = salt.getAttributeNS(null, "keyStorePath");
			String keyAlias = salt.getAttributeNS(null, "keyStoreKeyAlias");
			String ksPass = salt.getAttributeNS(null, "keyStorePassword");
			String keyPass = salt.getAttributeNS(null, "keyStoreKeyPassword");

			if (ksPath == null || ksPath.length() == 0 || keyAlias == null || keyAlias.length() == 0 || ksPass == null
					|| ksPass.length() == 0 || keyPass == null || keyPass.length() == 0) {

				log.error("Missing <Salt> keyStore attributes from attribute definition configuration.");
				throw new ResolutionPlugInException("Failed to initialize Attribute Definition PlugIn.");
			}

			try {
				KeyStore keyStore = KeyStore.getInstance("JCEKS");

				keyStore.load(new ShibResource(ksPath, this.getClass()).getInputStream(), ksPass.toCharArray());
				SecretKey secret = (SecretKey) keyStore.getKey(keyAlias, keyPass.toCharArray());

				if (usingDefaultSecret()) {
					log
							.warn("You are running the PersistentIDAttributeDefinition PlugIn with the default secret key as a salt.  This is UNSAFE!  Please change "
									+ "this configuration and restart the origin.");
				}
				this.salt = secret.getEncoded();

			} catch (KeyStoreException ex) {
				log
						.error("An error occurred while loading the java keystore.  Unable to initialize Attribute Definition PlugIn: "
								+ ex);
				throw new ResolutionPlugInException(
						"An error occurred while loading the java keystore.  Unable to initialize Attribute Definition PlugIn.");
			} catch (CertificateException ex) {
				log
						.error("The java keystore contained corrupted data.  Unable to initialize Attribute Definition PlugIn: "
								+ ex);
				throw new ResolutionPlugInException(
						"The java keystore contained corrupted data.  Unable to initialize Attribute Definition PlugIn.");
			} catch (NoSuchAlgorithmException ex) {
				log
						.error("Appropriate JCE provider not found in the java environment. Unable to initialize Attribute Definition PlugIn: "
								+ ex);
				throw new ResolutionPlugInException(
						"Appropriate JCE provider not found in the java environment. Unable to initialize Attribute Definition PlugIn.");
			} catch (IOException ex) {
				log
						.error("An error accessing while loading the java keystore.  Unable to initialize Attribute Definition PlugIn: "
								+ ex);
				throw new ResolutionPlugInException(
						"An error occurred while accessing the java keystore.  Unable to initialize Attribute Definition PlugIn.");
			} catch (UnrecoverableKeyException ex) {
				log
						.error("Secret could not be loaded from the java keystore.  Verify that the alias and password are correct: "
								+ ex);
				throw new ResolutionPlugInException(
						"Secret could not be loaded from the java keystore.  Verify that the alias and password are correct. ");
			}
		}
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn#resolve(edu.internet2.middleware.shibboleth.aa.attrresolv.ArpAttribute,
	 *      java.security.Principal, java.lang.String, edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies)
	 */
	public void resolve(ResolverAttribute attribute, Principal principal, String requester, Dependencies depends)
			throws ResolutionPlugInException {

		log.debug("Resolving attribute: (" + getId() + ")");

		if (requester == null || requester.equals("")) {
			log.debug("Could not create ID for unauthenticated requester.");
			attribute.setResolved();
			return;
		}

		String localId = null;

		// Resolve the correct local persistent identifier.
		if (!attributeDependencyIds.isEmpty()) {
			ResolverAttribute dep = depends.getAttributeResolution((String) attributeDependencyIds.iterator().next());
			if (dep != null) {
				Iterator vals = dep.getValues();
				if (vals.hasNext()) {
					log.debug("Found persistent ID value for attribute (" + getId() + ").");
					localId = (String) vals.next();
					if (vals.hasNext()) {
						log.error("An attribute dependency of attribute (" + getId()
								+ ") returned multiple values, expecting only one.");
						return;
					}
				} else {
					log.error("An attribute dependency of attribute (" + getId()
							+ ") returned no values, expecting one.");
					return;
				}
			} else {
				log.error("An attribute dependency of attribute (" + getId()
						+ ") was not included in the dependency chain.");
				return;
			}
		} else if (!connectorDependencyIds.isEmpty()) {
			Attributes attrs = depends.getConnectorResolution((String) connectorDependencyIds.iterator().next());
			if (attrs != null) {
				Attribute attr = attrs.get(localPersistentId);
				if (attr != null) {
					if (attr.size() != 1) {
						log.error("An attribute dependency of attribute (" + getId() + ") returned " + attr.size()
								+ " values, expecting only one.");
					} else {
						try {
							localId = (String) attr.get();
							log.debug("Found persistent ID value for attribute (" + getId() + ").");
						} catch (NamingException e) {
							log.error("A connector dependency of attribute (" + getId() + ") threw an exception: " + e);
							return;
						}
					}
				}
			} else {
				log.error("A connector dependency of attribute (" + getId() + ") did not return any attributes.");
				return;
			}
		} else {
			localId = principal.getName();
		}

		if (localId == null || localId.equals("")) {
			log.error("Specified source data not supplied from dependencies.  Unable to create ID.");
			attribute.setResolved();
			return;
		}

		if (lifeTime != -1) {
			attribute.setLifetime(lifeTime);
		}

		// Hash the data together to produce the persistent ID.
		try {
			MessageDigest md = MessageDigest.getInstance("SHA");
			md.update(requester.getBytes());
			md.update((byte) '!');
			md.update(localId.getBytes());
			md.update((byte) '!');
			String result = new String(Base64.encode(md.digest(salt)));

			attribute.registerValueHandler(new ScopedStringValueHandler(scope));
			attribute.addValue(result.replaceAll(System.getProperty("line.separator"), ""));
			attribute.setResolved();
		} catch (NoSuchAlgorithmException e) {
			log.error("Unable to load SHA-1 hash algorithm.");
		}
	}

	private boolean usingDefaultSecret() {

		byte[] defaultKey = new byte[]{(byte) 0xC7, (byte) 0x49, (byte) 0x80, (byte) 0xD3, (byte) 0x02, (byte) 0x4A,
				(byte) 0x61, (byte) 0xEF, (byte) 0x25, (byte) 0x5D, (byte) 0xE3, (byte) 0x2F, (byte) 0x57, (byte) 0x51,
				(byte) 0x20, (byte) 0x15, (byte) 0xC7, (byte) 0x49, (byte) 0x80, (byte) 0xD3, (byte) 0x02, (byte) 0x4A,
				(byte) 0x61, (byte) 0xEF};
		return Arrays.equals(defaultKey, salt);
	}
}
