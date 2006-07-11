
package edu.internet2.middleware.shibboleth.metadata;

/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import org.apache.log4j.Logger;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.w3c.dom.Element;

public class MetadataProviderFactory {

	private static Logger log = Logger.getLogger(MetadataProviderFactory.class.getName());

	public static MetadataProvider loadProvider(Element e) throws MetadataProviderException {

		String className = e.getAttribute("type");
		if (className == null || className.equals("")) {
			log.error("Metadata Provider requires specification of the attribute \"type\".");
			throw new MetadataProviderException("Failed to initialize Metadata Provider.");
		} else {
			try {
				Class[] params = {Class.forName("org.w3c.dom.Element"),};
				return (MetadataProvider) Class.forName(className).getConstructor(params).newInstance(new Object[]{e});
			} catch (Exception loaderException) {
				log.error("Failed to load Metadata Provider implementation class: " + loaderException);
				Throwable cause = loaderException.getCause();
				while (cause != null) {
					log.error("caused by: " + cause);
					cause = cause.getCause();
				}
				throw new MetadataProviderException("Failed to initialize Metadata Provider.");
			}
		}
	}
}
