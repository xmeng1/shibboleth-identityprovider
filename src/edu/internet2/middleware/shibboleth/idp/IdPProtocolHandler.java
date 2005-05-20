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

package edu.internet2.middleware.shibboleth.idp;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.SAMLException;
import org.opensaml.SAMLRequest;
import org.opensaml.SAMLResponse;

/**
 * Defines the processing for an IdP-supported protocol. A particular <code>IdPProtocolHandler</code> implementation
 * is registered to process requests delivered from one or more URL locations. Core IdP functionality is delivered
 * through the <code>IdPProtocolSupport</code> class.
 * 
 * @author Walter Hoehn
 */
public interface IdPProtocolHandler {

	/**
	 * Retreives a textual name for the handler for display purposes.
	 */
	public String getHandlerName();

	/**
	 * Runs the protocol-specific request processing.
	 * 
	 * @param samlRequest
	 *            the request that inititiated the transaction or null
	 * @param support
	 * @return a <code>SAMLResponse</code> object that should be delivered to the binding upon which the request was
	 *         received or null
	 */
	public SAMLResponse processRequest(HttpServletRequest request, HttpServletResponse response,
			SAMLRequest samlRequest, IdPProtocolSupport support) throws SAMLException, IOException, ServletException;

	/**
	 * Returns the locations for which this handler should process requests.
	 */
	public String[] getLocations();
}