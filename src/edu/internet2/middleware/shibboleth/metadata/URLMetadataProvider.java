
package edu.internet2.middleware.shibboleth.metadata;

import org.apache.log4j.Logger;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.w3c.dom.Element;

/**
 * Loads metadata from a URL specified in the IdP configuration.
 * 
 * @author Walter Hoehn
 */
public class URLMetadataProvider extends ShibbolethConfigurableMetadataProvider implements MetadataProvider {

	private static Logger log = Logger.getLogger(URLMetadataProvider.class.getName());

	public URLMetadataProvider(Element configuration) throws MetadataProviderException {

		super(configuration);

		// Grab the URL from the config
		String url = ((Element) configuration).getAttribute("url");
		if (url == null || url.equals("")) {
			log.error("Unable to load URL Metadata Provider.  A (url) attribute is required.  "
					+ "Add a (url) attribute to <MetadataProvider/>.");
			throw new MetadataProviderException("Required configuration not specified.");
		}

		// Grab the request timeout, if there is one. If not, use a reasonable default
		int requestTimeout = 1000 * 1 * 60; // 1 minute
		String rawRequestTimeout = ((Element) configuration).getAttribute("requestTimeout");
		if (rawRequestTimeout != null && !rawRequestTimeout.equals("")) {
			try {
				requestTimeout = Integer.valueOf(rawRequestTimeout);
			} catch (NumberFormatException nfe) {
				log.error("Unable to load URL Metadata Provider.  The (requestTimeout) attribute must be an integer.  "
						+ "Modify the (requestTimeout) attribute on <MetadataProvider/>.");
				throw new MetadataProviderException("Configuration is invalid.");
			}
		}

		// Construct provider from config
		try {
			provider = new org.opensaml.saml2.metadata.provider.URLMetadataProvider(url, requestTimeout);

			// If there is a cache duration, set it
			String rawMaxCacheDuration = ((Element) configuration).getAttribute("maxCacheDuration");
			if (rawMaxCacheDuration != null && !rawMaxCacheDuration.equals("")) {
				try {
					((org.opensaml.saml2.metadata.provider.URLMetadataProvider) provider).setMaxDuration(Integer
							.valueOf(rawMaxCacheDuration));
				} catch (NumberFormatException nfe) {
					log.error("Unable to load URL Metadata Provider.  The (maxCacheDuration) attribute must be "
							+ "an integer.  Modify the (maxCacheDuration) attribute on <MetadataProvider/>.");
					throw new MetadataProviderException("Configuration is invalid.");
				}
			}

		} catch (MetadataProviderException e) {
			log.error("Unable to load URL Metadata Provider: " + e);
			throw e;
		}
	}
}
