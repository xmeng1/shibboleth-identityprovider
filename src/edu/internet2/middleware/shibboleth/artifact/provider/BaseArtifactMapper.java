/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
 * provided with the distribution, if any, must include the following acknowledgment: "This product includes software
 * developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu> Internet2 Project.
 * Alternately, this acknowledegement may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear. Neither the name of Shibboleth nor the names of its contributors, nor Internet2, nor
 * the University Corporation for Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote
 * products derived from this software without specific prior written permission. For written permission, please contact
 * shibboleth@shibboleth.org Products derived from this software may not be called Shibboleth, Internet2, UCAID, or the
 * University Corporation for Advanced Internet Development, nor may Shibboleth appear in their name, without prior
 * written permission of the University Corporation for Advanced Internet Development. THIS SOFTWARE IS PROVIDED BY THE
 * COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE
 * DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. IN NO
 * EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC.
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.artifact.provider;

import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.log4j.Logger;
import org.opensaml.SAMLAssertion;
import org.opensaml.artifact.Artifact;
import org.opensaml.artifact.SAMLArtifactType0001;
import org.opensaml.artifact.SAMLArtifactType0002;
import org.opensaml.artifact.Util;

import edu.internet2.middleware.shibboleth.artifact.ArtifactMapper;
import edu.internet2.middleware.shibboleth.artifact.ArtifactMapping;
import edu.internet2.middleware.shibboleth.common.RelyingParty;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;

/**
 * Functionality common to most <code>ArtifactMapper</code> implementations, including creation and basic
 * encoding/decoding of arifiacts. Defers storage and lookup to subclasses.
 * 
 * @author Walter Hoehn
 */
public abstract class BaseArtifactMapper implements ArtifactMapper {

	private static Logger log = Logger.getLogger(BaseArtifactMapper.class.getName());
	// TODO init from config
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

	public Artifact generateArtifact(SAMLAssertion assertion, RelyingParty relyingParty) {

		// Generate the artifact
		Artifact artifact;

		// If the relying party prefers type 2 and we have the proper data, use it
		if (relyingParty.getPreferredArtifactType() == 2 && type2SourceLocation != null) {
			synchronized (md) {
				artifact = new SAMLArtifactType0002(Util.generateSourceId(md, relyingParty.getIdentityProvider()
						.getProviderId()), type2SourceLocation);
			}
			// Else, use type 1
		} else {
			if (relyingParty.getPreferredArtifactType() == 2) {
				log.warn("The relying party prefers Type 2 artifacts, but the mapper does not "
						+ "have a sourceLocation configured.  Using Type 1.");
			} else if (relyingParty.getPreferredArtifactType() != 1) {
				log.warn("The relying party prefers Type " + relyingParty.getPreferredArtifactType()
						+ " artifacts, but the mapper does not " + "support this type.  Using Type 1.");
			}

			synchronized (md) {
				artifact = new SAMLArtifactType0001(Util.generateSourceId(md, relyingParty.getIdentityProvider()
						.getProviderId()));
			}
		}

		// Delegate adding to extenders
		addAssertionImpl(artifact, new ArtifactMapping(artifact, assertion, relyingParty));

		// Return the encoded artifact
		return artifact;
	}

	/**
	 * Subclasses should implement artifact storage with this method.
	 */
	protected abstract void addAssertionImpl(Artifact artifact, ArtifactMapping mapping);

}