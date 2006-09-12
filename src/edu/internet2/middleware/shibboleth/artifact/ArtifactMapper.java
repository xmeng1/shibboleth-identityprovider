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

package edu.internet2.middleware.shibboleth.artifact;

import org.opensaml.SAMLAssertion;
import org.opensaml.artifact.Artifact;

import edu.internet2.middleware.shibboleth.common.ServiceProvider;

/**
 * Translates back and forth between SAML assertions and mapping strings (artifacts) needed for the SAML artifact
 * profile.
 * 
 * @author Walter Hoehn
 */
public interface ArtifactMapper {

	/**
	 * Generates an artifact from a SAML assertion.
	 * 
	 * @param assertion
	 *            the SAML assertion
	 * @param serviceProvider
	 *            the service provider on behalf of which the artifact is being created
	 * @return the artifact
	 */
	public Artifact generateArtifact(SAMLAssertion assertion, ServiceProvider serviceProvider);

	/**
	 * Recover an assertion that was previosly generated for a given artifact.
	 * 
	 * @param artifact
	 *            the artifact in question
	 * @return a mapping to the assertion
	 */

	public ArtifactMapping recoverAssertion(Artifact artifact);
}