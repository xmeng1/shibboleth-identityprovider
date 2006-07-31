
package edu.internet2.middleware.shibboleth.common.provider;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.opensaml.saml2.common.Extensions;
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

		private ShibPKIXMetadata metadataIterator;
		EntityDescriptor entity;

		private ShibbolethPKIXEngine(EntityDescriptor entity) {

			this.entity = entity;
		}

		@Override
		protected Iterator<PKIXValidationInformation> getValidationInformation(RoleDescriptor descriptor) {

			return new ShibPKIXMetadata();
		}

		private class ShibPKIXMetadata implements Iterator {

			private int iter = 0;

			public boolean hasNext() {

				// TODO this needs to do more than one
				return (iter < 1);
			}

			public PKIXValidationInformation next() {

				iter++;
				Extensions extensions = entity.getExtensions();
				for (XMLObject extension : extensions.getUnknownXMLObjects()) {
					if (extension.getElementQName().equals(KEY_AUTHORITY)) {

						if (!(extension instanceof ElementProxy)) {
							break;
						}

						// Find the verification depth for all anchors in this set
						int verifyDepth = 1;
						String rawVerifyDepth = ((ElementProxy) extension).getUnknownAttributes().get("VerifyDepth");
						// TODO doesn't work, need to fix attribute map
						if (rawVerifyDepth != null && !rawVerifyDepth.equals("")) {
							try {
								verifyDepth = Integer.parseInt(rawVerifyDepth);
							} catch (NumberFormatException nfe) {
								log.error("<KeyAuthority/> attribute (VerifyDepth) is not an "
										+ "integer, skipping <KeyAuthority/>.");
								break;
							}
						}

						// Find all trust anchors and revocation lists in the KeyInfo
						Set<X509Certificate> trustAnchors = new HashSet<X509Certificate>();
						Set<X509CRL> revocationLists = new HashSet<X509CRL>();
						for (XMLObject subExtension : ((ElementProxy) extension).getUnknownXMLObjects()) {
							if (subExtension instanceof KeyInfo) {
								trustAnchors.addAll(((KeyInfo) subExtension).getCertificates());
								revocationLists.addAll(((KeyInfo) subExtension).getCRLs());
							}
						}

						log.debug("Found Shibboleth Key Authority Metadata: Verification depth: " + verifyDepth
								+ " Trust Anchors: " + trustAnchors.size() + " Revocation Lists: "
								+ revocationLists.size() + ".");
						return new PKIXValidationInformation(1, trustAnchors, revocationLists);

					}
				}
				return null;
			}

			public void remove() {

				throw new UnsupportedOperationException();

			}

		}

		/*
		 * class XMLKeyAuthority implements KeyAuthority { private int depth = 1; private ArrayList keys = new
		 * ArrayList(); XMLKeyAuthority(Element e) { if (e.hasAttributeNS(null, "VerifyDepth")) depth =
		 * Integer.parseInt(e.getAttributeNS(null, "VerifyDepth")); e = XML.getFirstChildElement(e, XML.XMLSIG_NS,
		 * "KeyInfo"); while (e != null) { try { keys.add(new KeyInfo(e, null)); } catch (XMLSecurityException e1) {
		 * log.error("unable to process ds:KeyInfo element: " + e1.getMessage()); } e = XML.getNextSiblingElement(e,
		 * XML.XMLSIG_NS, "KeyInfo"); } } public int getVerifyDepth() { return depth; } public Iterator getKeyInfos() {
		 * return keys.iterator(); } }
		 */
	}
}
