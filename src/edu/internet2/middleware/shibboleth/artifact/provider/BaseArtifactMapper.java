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

package edu.internet2.middleware.shibboleth.artifact.provider;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.log4j.Logger;
import org.opensaml.SAMLAssertion;
import org.opensaml.artifact.Artifact;
import org.opensaml.artifact.SAMLArtifactType0001;
import org.opensaml.artifact.SAMLArtifactType0002;
import org.opensaml.artifact.Util;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.artifact.ArtifactMapper;
import edu.internet2.middleware.shibboleth.artifact.ArtifactMapping;
import edu.internet2.middleware.shibboleth.common.ServiceProvider;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;

/**
 * Functionality common to most <code>ArtifactMapper</code> implementations, including creation and basic
 * encoding/decoding of arifiacts. Defers storage and lookup to subclasses.
 * 
 * @author Walter Hoehn
 */
public abstract class BaseArtifactMapper implements ArtifactMapper {

	private static Logger log = Logger.getLogger(BaseArtifactMapper.class.getName());
	private URI type2SourceLocation;
	private MessageDigest md;

	public BaseArtifactMapper() throws ShibbolethConfigurationException {

		try {
			md = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			log.error("No support found for SHA-1 digest algorithm: " + e);
			throw new ShibbolethConfigurationException(
					"The IdP Artifact Mapper requires JCE support for the SHA-1 digest algorithm.");
		}
	}

	public BaseArtifactMapper(Element config) throws ShibbolethConfigurationException {

		this();

		String attribute = config.getAttribute("sourceLocation");
		if (attribute != null && !attribute.equals("")) {
			try {
				type2SourceLocation = new URI(attribute);
				log.debug("Artifact Mapper configured to issue Type 1 artifacts & Type 2 artifacts with a "
						+ "sourceLocation of (" + type2SourceLocation + ").");
			} catch (URISyntaxException e) {
				log.error("(sourceLocation) attribute for <ArtifactMapper/> is not a valid URI: " + e);
				throw new ShibbolethConfigurationException("Unable to initialize Artifact mapper");
			}
		} else {
			log.debug("No (sourceLocaton) attribute found for element <ArtifactMapper/>.  The Artifact Mapper will "
					+ "only be able to send Type 1 artifacts.");
		}
	}

	public Artifact generateArtifact(SAMLAssertion assertion, ServiceProvider serviceProvider) {

		// Generate the artifact
		Artifact artifact;

		// If the relying party prefers type 2 and we have the proper data, use it
		if (serviceProvider.getPreferredArtifactType() == 2 && type2SourceLocation != null) {
			artifact = new SAMLArtifactType0002(new org.opensaml.artifact.URI(type2SourceLocation.toString()));
			// Else, use type 1
		} else {
			if (serviceProvider.getPreferredArtifactType() == 2) {
				log.warn("The relying party prefers Type 2 artifacts, but the mapper does not "
						+ "have a sourceLocation configured.  Using Type 1.");
			} else if (serviceProvider.getPreferredArtifactType() != 1) {
				log.warn("The relying party prefers Type " + serviceProvider.getPreferredArtifactType()
						+ " artifacts, but the mapper does not " + "support this type.  Using Type 1.");
			}

			synchronized (md) {
				artifact = new SAMLArtifactType0001(Util.generateSourceId(md, serviceProvider.getIdentityProvider()
						.getProviderId()));
			}
		}

		// Delegate adding to extenders
		addAssertionImpl(artifact, new ArtifactMapping(artifact, assertion, serviceProvider));

		// Return the encoded artifact
		return artifact;
	}

	/**
	 * Subclasses should implement artifact storage with this method.
	 */
	protected abstract void addAssertionImpl(Artifact artifact, ArtifactMapping mapping);

}