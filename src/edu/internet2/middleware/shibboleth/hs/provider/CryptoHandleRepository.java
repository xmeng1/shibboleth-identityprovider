/* 
 * The Shibboleth License, Version 1. 
 * Copyright (c) 2002 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
 * 
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this 
 * list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution, if any, must include 
 * the following acknowledgment: "This product includes software developed by 
 * the University Corporation for Advanced Internet Development 
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement 
 * may appear in the software itself, if and wherever such third-party 
 * acknowledgments normally appear.
 * 
 * Neither the name of Shibboleth nor the names of its contributors, nor 
 * Internet2, nor the University Corporation for Advanced Internet Development, 
 * Inc., nor UCAID may be used to endorse or promote products derived from this 
 * software without specific prior written permission. For written permission, 
 * please contact shibboleth@shibboleth.org
 * 
 * Products derived from this software may not be called Shibboleth, Internet2, 
 * UCAID, or the University Corporation for Advanced Internet Development, nor 
 * may Shibboleth appear in their name, without prior written permission of the 
 * University Corporation for Advanced Internet Development.
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK 
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY 
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.hs.provider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;
import edu.internet2.middleware.shibboleth.hs.HandleRepository;
import edu.internet2.middleware.shibboleth.hs.HandleRepositoryException;

/**
 * <code>HandleRepository</code> implementation that employs the use of a shard secret
 * in order to transmit identity information.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public class CryptoHandleRepository extends BaseHandleRepository implements HandleRepository {

	SecretKey secret;

	public CryptoHandleRepository(Properties properties) throws HandleRepositoryException {
		super(properties);
		KeyGenerator keyGen;
		try {
			keyGen = KeyGenerator.getInstance("DESede");
		} catch (NoSuchAlgorithmException e) {
			System.err.println(e);
			return;
		}
        secret = keyGen.generateKey();
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.hs.HandleRepository#getHandle(Principal)
	 */
	public String getHandle(AuthNPrincipal principal) {
		try {

			HandleEntry handleEntry = createHandleEntry(principal);
			ByteArrayOutputStream outStream = new ByteArrayOutputStream();
			ObjectOutput objectStream = new ObjectOutputStream(outStream);
			objectStream.writeObject(handleEntry);
			objectStream.flush();
			objectStream.close();

			Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secret);
			byte[] cipherTextHandle = cipher.doFinal(outStream.toByteArray());

			String handle = new BASE64Encoder().encode(cipherTextHandle);
			return handle.replaceAll(System.getProperty("line.separator"), "");

		} catch (Exception e) {
			System.err.println(e);
			return null;
		}
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.hs.HandleRepository#getPrincipal(String)
	 */
	public AuthNPrincipal getPrincipal(String handle) {
		
		try {
			Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, secret);
			byte[] objectArray = cipher.doFinal(new BASE64Decoder().decodeBuffer(handle));

			ObjectInputStream objectStream = new ObjectInputStream(new ByteArrayInputStream(objectArray));
			HandleEntry handleEntry = (HandleEntry) objectStream.readObject();
			System.err.println(handleEntry.principal.getName());
			return handleEntry.principal;
			
		} catch (Exception e) {
			System.err.println(e);
			return null;
		}
	}

}
