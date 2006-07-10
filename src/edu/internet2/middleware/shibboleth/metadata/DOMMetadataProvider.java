
package edu.internet2.middleware.shibboleth.metadata;

import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.w3c.dom.Element;

/**
 * Loads metadata directly from the IdP configuration.
 * 
 * @author Walter Hoehn
 */
/*
 * We could do without this class, I guess, since the OpenSAML version has the right constructor; but it seems prudent
 * to put it in the same hierarchy with its peers.
 */
public class DOMMetadataProvider extends ShibbolethConfigurableMetadataProvider implements MetadataProvider {

	public DOMMetadataProvider(Element configuration) throws MetadataProviderException {

		super(configuration);

		provider = new org.opensaml.saml2.metadata.provider.DOMMetadataProvider(configuration);

	}

}
