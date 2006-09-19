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

package edu.internet2.middleware.shibboleth.common;

/**
 * Defines a configuration relationship between service providers and an identity provider. In Shibboleth parlance, a
 * relying party represents a SP or group of SPs (perhaps a federation).
 * 
 * @author Walter Hoehn
 */
public interface RelyingParty {

	/**
	 * Returns the appropriate identity provider to create assertions for this relying party.
	 * 
	 * @return the identity provider
	 */
	public IdentityProvider getIdentityProvider();

	/**
	 * A boolean indication of whether internal errors should be transmitted to this {@link RelyingParty}
	 */
	public boolean passThruErrors();

	/**
	 * A boolean indication of whether attributes should be pushed without regard for the profile (POST vs. Artifact).
	 * This should be be mutually exclusive with forceAttributeNoPush().
	 */
	public boolean forceAttributePush();

	/**
	 * A boolean indication of whether attributes should be NOT pushed without regard for the profile (POST vs.
	 * Artifact).
	 */
	public boolean forceAttributeNoPush();

	/**
	 * A boolean indication of whether the default SSO browser profile should be POST or Artifact. "true" indicates POST
	 * and "false" indicates Artifact.
	 */
	public boolean defaultToPOSTProfile();

	/**
	 * A boolean indication of whether assertions issued to this Relying Party should be digitally signed (This is in
	 * addition to profile-specific signing).
	 */
	public boolean wantsAssertionsSigned();

	/**
	 * A boolean indication of whether attributes sent with an authentication response should be included in the same
	 * assertion or left in a second assertion for compatibility with broken SAML products.
	 */
	public boolean singleAssertion();

	/**
	 * Returns the type of SAML Artifact that this appropriate for use with this Relying Party.
	 */
	public int getPreferredArtifactType();

	/**
	 * Returns the default "TARGET" attribute to be used with the artifact profile or null if none is specified.
	 */
	public String getDefaultTarget();

	/**
	 * Provides a mechanism for extension developers to pass relying party specific data into their extensions.
	 */
	public String getCustomAttribute(String name);

}
