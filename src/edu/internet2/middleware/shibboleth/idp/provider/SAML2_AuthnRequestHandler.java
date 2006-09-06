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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolHandler;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolSupport;
import edu.internet2.middleware.shibboleth.idp.RequestHandlingException;

/**
 * @author Walter Hoehn
 */
public class SAML2_AuthnRequestHandler extends SAML2ProtcolHandler implements IdPProtocolHandler {

	public SAML2_AuthnRequestHandler(Element config) throws ShibbolethConfigurationException {

		super(config);
	}

	public String getHandlerName() {

		return "SAML v2 Authn Request";
	}

	public void processRequest(HttpServletRequest request, HttpServletResponse response, IdPProtocolSupport support)
			throws RequestHandlingException, ServletException {

	// TODO implement
	// TODO support redirect
	// TODO support artifact
	// TODO support POST

	}

}
