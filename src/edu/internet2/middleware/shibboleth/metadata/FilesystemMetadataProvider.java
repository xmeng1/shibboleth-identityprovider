
package edu.internet2.middleware.shibboleth.metadata;

import java.io.IOException;

import org.apache.log4j.Logger;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.ShibResource;
import edu.internet2.middleware.shibboleth.common.ShibResource.ResourceNotAvailableException;

/**
 * Loads metadata from a path specified in the IdP configuration.
 * 
 * @author Walter Hoehn
 */
public class FilesystemMetadataProvider extends ShibbolethConfigurableMetadataProvider implements MetadataProvider {

	private static Logger log = Logger.getLogger(FilesystemMetadataProvider.class.getName());

	public FilesystemMetadataProvider(Element configuration) throws MetadataProviderException {

		super(configuration);

		// Grab the path from the config
		String path = ((Element) configuration).getAttribute("path");
		if (path == null || path.equals("")) {
			log.error("Unable to load File System Metadata Provider.  A (path) attribute is required.  "
					+ "Add a (path) attribute to <MetadataProvider/>.");
			throw new MetadataProviderException("Required configuration not specified.");
		}

		// Construct provider from config
		try {
			provider = new org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider(new ShibResource(path)
					.getFile());

		} catch (MetadataProviderException e) {
			log.error("Unable to load URL Metadata Provider: " + e);
			throw e;
		} catch (ResourceNotAvailableException e) {
			log.error("Unable to load File System Metadata Provider.  Could not access file at (" + path + ").");
			throw new MetadataProviderException("Supplied configuration is invalid.");
		} catch (IOException e) {
			log.error("Unable to load File System Metadata Provider.  Error while reading file: " + e);
			throw new MetadataProviderException("Supplied configuration is invalid.");
		}
	}
}
