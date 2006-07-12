
package edu.internet2.middleware.shibboleth.metadata;

import java.util.List;

import javax.xml.namespace.QName;

import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataFilter;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObject;
import org.w3c.dom.Element;

/**
 * Base class for <code>MetadataProvider</code> implementations that can be loaded based on the IdP runtime
 * configuration. Implementors should create a constructor that accepts a configuration <code>Element</code> and sets
 * the provider field.
 * 
 * @author Walter Hoehn
 */
public abstract class ShibbolethConfigurableMetadataProvider implements MetadataProvider {

	protected org.opensaml.saml2.metadata.provider.MetadataProvider provider;

	public ShibbolethConfigurableMetadataProvider(Element configuration) {

	}

	public boolean requireValidMetadata() {

		return provider.requireValidMetadata();
	}

	public void setRequireValidMetadata(boolean requireValidMetadata) {

		provider.setRequireValidMetadata(requireValidMetadata);

	}

	public MetadataFilter getMetadataFilter() {

		return provider.getMetadataFilter();
	}

	public void setMetadataFilter(MetadataFilter newFilter) throws MetadataProviderException {

		provider.setMetadataFilter(newFilter);

	}

	public EntityDescriptor getEntityDescriptor(String entityID) throws MetadataProviderException {

		return provider.getEntityDescriptor(entityID);
	}

	public List<RoleDescriptor> getRole(String entityID, QName roleName) throws MetadataProviderException {

		return provider.getRole(entityID, roleName);
	}

	public XMLObject getMetadata() throws MetadataProviderException {

		return provider.getMetadata();
	}

	public EntitiesDescriptor getEntitiesDescriptor(String name) throws MetadataProviderException {

		return provider.getEntitiesDescriptor(name);
	}

	public RoleDescriptor getRole(String entityID, QName roleName, String supportedProtocol)
			throws MetadataProviderException {

		return provider.getRole(entityID, roleName, supportedProtocol);
	}
}
