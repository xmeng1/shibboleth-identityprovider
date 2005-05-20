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

package edu.internet2.middleware.shibboleth.idp.provider;

import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolHandler;

/**
 * @author Walter Hoehn
 */
public abstract class BaseServiceHandler extends BaseHandler implements IdPProtocolHandler {

	/**
	 * Required DOM-based constructor.
	 */
	public BaseServiceHandler(Element config) throws ShibbolethConfigurationException {

		super(config);
	}

	private static Logger log = Logger.getLogger(BaseServiceHandler.class.getName());

	protected static X509Certificate getCredentialFromProvider(HttpServletRequest req) {

		X509Certificate[] certArray = (X509Certificate[]) req.getAttribute("javax.servlet.request.X509Certificate");
		if (certArray != null && certArray.length > 0) { return certArray[0]; }
		return null;
	}

	protected class InvalidProviderCredentialException extends Exception {

		public InvalidProviderCredentialException(String message) {

			super(message);
		}
	}
}