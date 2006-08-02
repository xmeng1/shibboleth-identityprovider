
package edu.internet2.middleware.shibboleth.common.provider;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Set;

import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.security.TrustEngine;
import org.opensaml.security.X509EntityCredential;
import org.opensaml.security.impl.AbstractPKIXTrustEngine;
import org.opensaml.security.impl.InlinePKIKeyTrustEngine;
import org.opensaml.xml.ElementProxy;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.signature.KeyInfo;

/**
 * <code>TrustEngine</code> implementation that first attempts to do standard SAML2 inline key validation and then
 * falls back on PKIX validation against key authorities included in shibboleth-specific extensions to SAML 2 metadata.
 * 
 * @author Walter Hoehn
 */
public class ShibbolethTrustEngine extends InlinePKIKeyTrustEngine implements TrustEngine<X509EntityCredential> {

	private static Logger log = Logger.getLogger(ShibbolethTrustEngine.class.getName());
	private static final String KEY_AUTHORITY_LOCAL_NAME = "KeyAuthority";
	private static final String CUSTOM_METADATA_NS = "urn:mace:shibboleth:metadata:1.0";
	private static final QName KEY_AUTHORITY = new QName(CUSTOM_METADATA_NS, KEY_AUTHORITY_LOCAL_NAME);

	@Override
	public boolean validate(X509EntityCredential entityCredential, RoleDescriptor descriptor) {

		// If we can successfully validate with an inline key, that's fine
		boolean defaultValidation = super.validate(entityCredential, descriptor);
		if (defaultValidation == true) { return true; }

		// Make sure we have the data we need
		if (descriptor == null || entityCredential == null) {
			log.error("Appropriate data was not supplied for trust evaluation.");
			return false;
		}

		// If not, try PKIX validation against the shib-custom metadata extensions
		if (descriptor.getParent() == null || !(descriptor.getParent() instanceof EntityDescriptor)) {
			log.debug("Inline validation was unsuccessful.  Unable to attempt PKIX validation "
					+ "because we don't have a complete metadata tree.");
			return false;

		} else {
			log.debug("Inline validation was unsuccessful.  Attmping PKIX...");
			boolean pkixValid = new ShibbolethPKIXEngine((EntityDescriptor) descriptor.getParent()).validate(
					entityCredential, descriptor);
			if (pkixValid) {
				log.debug("PKIX validation was successful.");
			} else {
				log.debug("PKIX validation was unsuccessful.");
			}
			return pkixValid;
		}
	}

	/**
	 * Pulls <code>PKIXValidationInformation</code> out of Shibboleth-specific metadata extensions and runs the
	 * results against OpenSAML's PKIX trust engine. Recurses backwards through the metadata tree, attempting PKIX
	 * validation at each level that contains a <KeyAuthority/> element. Metadata is evaluated in a lazy fashion.
	 */
	private class ShibbolethPKIXEngine extends AbstractPKIXTrustEngine implements TrustEngine<X509EntityCredential> {

		EntityDescriptor entity;

		private ShibbolethPKIXEngine(EntityDescriptor entity) {

			this.entity = entity;
		}

		@Override
		protected Iterator<PKIXValidationInformation> getValidationInformation(RoleDescriptor descriptor) {

			return new ShibPKIXMetadata(entity);
		}

		private class ShibPKIXMetadata implements Iterator<PKIXValidationInformation> {

			private EntityDescriptor root;
			private EntitiesDescriptor currentParent;

			private ShibPKIXMetadata(EntityDescriptor entity) {

				this.root = entity;
			}

			private ElementProxy getNextKeyAuthority(boolean consume) {

				Extensions extensions = null;
System.err.println("entity part.");
				// Look for an unconsumed key authority on the entity descriptor first
				if (root != null) {
					extensions = root.getExtensions();
					if (consume) {
						if (root.getParent() instanceof EntitiesDescriptor) {
							currentParent = (EntitiesDescriptor) root.getParent();
						}
						root = null;
					}
				}

				if (extensions != null) {
					for (XMLObject extension : extensions.getUnknownXMLObjects()) {
						if (extension.getElementQName().equals(KEY_AUTHORITY) && extension instanceof ElementProxy) {
							log.debug("Using Key Authority from entity descriptor.");
							return (ElementProxy) extension;
						}
					}
				}
System.err.println("entities part.");
				// Alright, we didn't find one... try the parent
				while (currentParent != null) {
System.err.println("foobar");
					extensions = currentParent.getExtensions();
					if (consume) {
						if (currentParent.getParent() instanceof EntitiesDescriptor) {
							currentParent = (EntitiesDescriptor) currentParent.getParent();
						}
					}

					if (extensions != null) {
						for (XMLObject extension : extensions.getUnknownXMLObjects()) {
							if (extension.getElementQName().equals(KEY_AUTHORITY) && extension instanceof ElementProxy) {
								log.debug("Using Key Authority from entities descriptor.");
								return (ElementProxy) extension;
							}
						}
					}
				}

				return null;
			}

			public boolean hasNext() {

				System.err.println("hasNext()");
				return (getNextKeyAuthority(false) != null);
			}

			public PKIXValidationInformation next() {
System.err.println("next()");
				// Construct PKIX validation information from Shib metadata
				ElementProxy keyAuthority = getNextKeyAuthority(true);
				if (keyAuthority == null) { throw new NoSuchElementException(); }

				// Find the verification depth for all anchors in this set
				int verifyDepth = 1;
				String rawVerifyDepth = keyAuthority.getUnknownAttributes().get("VerifyDepth");
				// TODO doesn't work, need to fix attribute map
				if (rawVerifyDepth != null && !rawVerifyDepth.equals("")) {
					try {
						verifyDepth = Integer.parseInt(rawVerifyDepth);
					} catch (NumberFormatException nfe) {
						log.error("<KeyAuthority/> attribute (VerifyDepth) is not an "
								+ "integer, defaulting to most strict depth of (1).");
						verifyDepth = 1;
					}
				}

				// Find all trust anchors and revocation lists in the KeyInfo
				Set<X509Certificate> trustAnchors = new HashSet<X509Certificate>();
				Set<X509CRL> revocationLists = new HashSet<X509CRL>();
				for (XMLObject subExtension : keyAuthority.getUnknownXMLObjects()) {
					if (subExtension instanceof KeyInfo) {
						trustAnchors.addAll(((KeyInfo) subExtension).getCertificates());
						revocationLists.addAll(((KeyInfo) subExtension).getCRLs());
					}
				}

				log.debug("Found Shibboleth Key Authority Metadata: Verification depth: " + verifyDepth
						+ " Trust Anchors: " + trustAnchors.size() + " Revocation Lists: " + revocationLists.size()
						+ ".");
				return new PKIXValidationInformation(1, trustAnchors, revocationLists);

			}

			public void remove() {

				throw new UnsupportedOperationException();
			}

		}
	}
}
