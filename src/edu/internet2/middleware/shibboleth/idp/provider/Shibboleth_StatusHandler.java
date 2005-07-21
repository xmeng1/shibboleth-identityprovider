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

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.SAMLException;
import org.opensaml.SAMLRequest;
import org.opensaml.SAMLResponse;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolHandler;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolSupport;

/**
 * Special handler that allows one to "ping" the IdP to make sure it is alive
 * 
 * @author Walter Hoehn
 */
public class Shibboleth_StatusHandler extends BaseHandler implements IdPProtocolHandler {

	public Shibboleth_StatusHandler(Element config) throws ShibbolethConfigurationException {

		super(config);
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.idp.IdPProtocolHandler#getHandlerName()
	 */
	public String getHandlerName() {

		return "Shibboleth Status";
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.idp.IdPProtocolHandler#processRequest(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse, org.opensaml.SAMLRequest,
	 *      edu.internet2.middleware.shibboleth.idp.IdPProtocolSupport)
	 */
	public SAMLResponse processRequest(HttpServletRequest request, HttpServletResponse response,
			SAMLRequest samlRequest, IdPProtocolSupport support) throws SAMLException, IOException, ServletException {

		response.setContentType("text/plain");
		response.getWriter().println("AVAILABLE");
		return null;
	}

}
