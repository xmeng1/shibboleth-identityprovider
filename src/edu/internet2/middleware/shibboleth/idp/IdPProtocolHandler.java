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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
	 * Runs the protocol-specific request processing. Responsible for updating the <code>HttpServletResponse</code>.
	 * 
	 * @throws RequestHandlingException
	 *             if the handler is unable to successfully respond with a successfull protocol exchange or a
	 *             protocol-defined error message
	 */
	public void processRequest(HttpServletRequest request, HttpServletResponse response, IdPProtocolSupport support)
			throws RequestHandlingException, ServletException;

	/**
	 * Returns the locations for which this handler should process requests.
	 */
	public String[] getLocations();
}