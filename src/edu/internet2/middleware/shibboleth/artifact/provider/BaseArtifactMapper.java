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

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.apache.log4j.Logger;
import org.opensaml.SAMLAssertion;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import edu.internet2.middleware.shibboleth.artifact.ArtifactMapper;
import edu.internet2.middleware.shibboleth.artifact.ArtifactMapping;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.hs.HSRelyingParty;

/**
 * Functionality common to most <code>ArtifactMapper</code> implementations, including creation and basic
 * encoding/decoding of arifiacts. Defers storage and lookup to subclasses.
 * 
 * @author Walter Hoehn
 */
public abstract class BaseArtifactMapper implements ArtifactMapper {

	private static Logger	log			= Logger.getLogger(BaseArtifactMapper.class.getName());
	private static byte[]	typeCode	= {0, 1};

	private SecureRandom	random		= new SecureRandom();
	private MessageDigest	md;

	public BaseArtifactMapper() throws ShibbolethConfigurationException {
		try {
			md = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			log.error("No support found for SHA-1 digest algorithm: " + e);
			throw new ShibbolethConfigurationException(
					"The IdP Artifact Mapper requires JCE support for the SHA-1 digest algorithm.");
		}

	}

	public ArtifactMapping recoverAssertion(String artifact) {

		try {
			//Decode the artifact
			byte[] decoded = new BASE64Decoder().decodeBuffer(artifact);
			if (decoded.length != 42) {
				log.error("Invalid artifact length.");
				return null;
			}

			//Check the type
			if (decoded[0] != typeCode[0] || decoded[1] != typeCode[1]) {
				log.error("Incorrect artifact type code.");
				return null;
			}

			//Grab the assertion handle
			byte[] assertionHandle = new byte[20];
			for (int assertionHandleCount = 0, decodedCount = 22; assertionHandleCount < assertionHandle.length; assertionHandleCount++, decodedCount++) {
				assertionHandle[assertionHandleCount] = decoded[decodedCount];
			}
			String stringHandle = new String(assertionHandle);

			//delegate recovery to extenders
			return recoverAssertionImpl(stringHandle);

		} catch (IOException e) {
			log.error("Artifact not properly Base64 encoded.");
			return null;
		}
	}

	public String generateArtifact(SAMLAssertion assertion, HSRelyingParty relyingParty) {

		byte[] allArtifactComponents = new byte[42];

		// Add typecode
		allArtifactComponents[0] = typeCode[0];
		allArtifactComponents[1] = typeCode[1];

		// Add SourceID
		byte[] sourceID = new byte[20];
		synchronized (md) {
			sourceID = md.digest(relyingParty.getIdentityProvider().getProviderId().getBytes());
		}
		for (int sourceIdCount = 0, allComponentCount = 2; sourceIdCount < sourceID.length; sourceIdCount++, allComponentCount++) {
			allArtifactComponents[allComponentCount] = sourceID[sourceIdCount];
		}

		// Add Asserton Handle
		byte[] buffer = new byte[20];
		random.nextBytes(buffer);
		for (int assertionHandleCount = 0, allComponentCount = 22; assertionHandleCount < buffer.length; assertionHandleCount++, allComponentCount++) {
			allArtifactComponents[allComponentCount] = buffer[assertionHandleCount];
		}

		// Cache the assertion handle
		String assertionHandle = new String(buffer);

		// Delegate adding to extenders
		addAssertionImpl(assertionHandle, new ArtifactMapping(assertionHandle, assertion, relyingParty));

		// Return the encoded artifact
		return new BASE64Encoder().encode(allArtifactComponents);
	}

	/**
	 * Subclasses should implement artifact storage with this method.
	 */
	protected abstract void addAssertionImpl(String assertionHandle, ArtifactMapping mapping);

	/**
	 * Subclasses should implement artifact lookup with this method.
	 * 
	 * @param stringHandle
	 *            the artifact string
	 */
	protected abstract ArtifactMapping recoverAssertionImpl(String artifact);

}