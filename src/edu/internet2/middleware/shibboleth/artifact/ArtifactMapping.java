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
 * Encapsulates internal data/functionality that is tied to a SAML artifact.
 * 
 * @author Walter Hoehn
 */
public class ArtifactMapping {

	private Artifact artifact;
	private long expirationTime;
	private SAMLAssertion assertion;
	private String serviceProviderId;

	public ArtifactMapping(Artifact artifact, SAMLAssertion assertion, ServiceProvider sp) {

		this.artifact = artifact;
		this.assertion = assertion;
		expirationTime = System.currentTimeMillis() + (1000 * 60 * 5); // in 5 minutes
		serviceProviderId = sp.getProviderId();
	}

	/**
	 * Boolean indication of whether the artifact is expired.
	 */
	public boolean isExpired() {

		if (System.currentTimeMillis() > expirationTime) { return true; }
		return false;
	}

	/**
	 * Boolean indication of whether the artifact was created on behalf of a specified SP.
	 */
	public boolean isCorrectProvider(ServiceProvider sp) {

		if (sp.getProviderId().equals(serviceProviderId)) { return true; }
		return false;
	}

	/**
	 * Retrieves the SAML assertion associated with the artifact.
	 */
	public SAMLAssertion getAssertion() {

		return assertion;
	}

	/**
	 * Retrieves the SP on behalf of which the artifact was originally created.
	 */
	public String getServiceProviderId() {

		return serviceProviderId;
	}

}