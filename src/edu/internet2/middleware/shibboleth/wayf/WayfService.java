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

package edu.internet2.middleware.shibboleth.wayf;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import javax.servlet.GenericServlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.xml.Parser;

/**
 * A servlet implementation of the Shibboleth WAYF service. Allows a browser
 * user to select from among a group of origin sites. User selection is
 * optionally cached and the user is forwarded to the HandleService appropriate
 * to his selection.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */
public class WayfService extends HttpServlet {

	private String wayfConfigFileLocation;
	private static final Logger log = Logger.getLogger(WayfService.class.getName());
	
	private List /*<DiscoveryServiceHandler>*/ discoveryServices = new ArrayList /*<DiscoveryServiceHandler>*/();
	
	/**
	 * @see GenericServlet#init()
	 */
	public void init() throws ServletException {

		super.init();

		wayfConfigFileLocation = getServletContext().getInitParameter("WAYFConfigFileLocation");
		if (wayfConfigFileLocation == null) {
			wayfConfigFileLocation = getServletConfig().getInitParameter("WAYFConfigFileLocation");
		}
		if (wayfConfigFileLocation == null) {
			wayfConfigFileLocation = "/conf/wayfconfig.xml";
		}

		try {
			
			Document doc = Parser.loadDom(wayfConfigFileLocation, true);
			
			NodeList itemElements = doc.getDocumentElement().getElementsByTagNameNS(HandlerConfig.configNameSpace, "Default");
			
			HandlerConfig defaultHandlerConfig;
			
			if (itemElements.getLength() == 1) {
				
				Element element = (Element) itemElements.item(0);
				String attribute = element.getAttribute("location");
				
				if (attribute != null && !attribute.equals("")) {
					
					log.error("<Default> element cannot contain a location attribute");
					throw new ShibbolethConfigurationException("<Default> element cannot contain a location attribute");
					
				}

				attribute = element.getAttribute("default");
				
				if (attribute != null && !attribute.equals("")) {

					log.error("<Default> element cannot contain a default attribute");
					throw new ShibbolethConfigurationException("<Default> element cannot contain a default attribute");
					
				}

				itemElements = element.getElementsByTagName("Federation");
				
				if (itemElements.getLength() != 0) {
					
					log.error("<Default> element cannot contain <Federation> elements");
					throw new ShibbolethConfigurationException("<Default> element cannot contain <Federation> elements");

				}
			    				
				defaultHandlerConfig = new HandlerConfig(element, new HandlerConfig());
			
			} else if (itemElements.getLength() == 0) {

				defaultHandlerConfig = new HandlerConfig();
			
			} else {
				log.error("Must specify exactly one <Default> element");
				throw new ShibbolethConfigurationException("Must specify exactly one <Default> element");
			}
						
			//
			// Load metadata
			//
			Hashtable /*<String, IdPSiteSet>*/ siteSets = new Hashtable /*<String, IdPSiteSet>*/();

			itemElements = doc.getDocumentElement().getElementsByTagNameNS(HandlerConfig.configNameSpace,
					"MetadataProvider");
			
			for (int i = 0; i < itemElements.getLength(); i++) {
				
				Element element = (Element) itemElements.item(i);
				
				IdPSiteSet siteset = new IdPSiteSet(element);
				
				siteSets.put(siteset.getIdentifier(), siteset);
			}
			if (siteSets.size() < 1) {
				log.error("No Metadata Provider metadata loaded.");
				throw new ShibbolethConfigurationException("Could not load SAML metadata.");
			}
			
			//
			// Load service handlers
			//
			itemElements = doc.getDocumentElement().getElementsByTagNameNS(HandlerConfig.configNameSpace,
					"DiscoveryServiceHandler");
			
			for (int i = 0; i < itemElements.getLength(); i++) {
				
				discoveryServices.add(new DiscoveryServiceHandler((Element)itemElements.item(i), siteSets, defaultHandlerConfig));

			}
			//if ()

		} catch (IOException e) {
			if (log != null) {
				log.fatal("Error Loading WAYF configuration file.", e);
			}
			throw new ServletException("Error Loading WAYF configuration file.", e);
		} catch (Exception e) {
			//
			// All other exceptions are from the parsing
			//
			if (log != null) {
				log.fatal("Error parsing WAYF configuration file.", e);
			}
			throw new ServletException("Error parsing WAYF configuration file.", e);
		}
		
		log.info("WAYF initialization completed.");
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest, HttpServletResponse)
	 */
	public void doGet(HttpServletRequest req, HttpServletResponse res) {

		
		log.info("Handling WAYF request.");
		// Tell the browser not to cache the WAYF page
		res.setHeader("Cache-Control", "no-cache");
		res.setHeader("Pragma", "no-cache");
		res.setDateHeader("Expires", 0);

		DiscoveryServiceHandler serviceHandler = lookupServiceHandler(req); 
		
		serviceHandler.doGet(req, res);
		
	}

	private DiscoveryServiceHandler lookupServiceHandler(HttpServletRequest req) {

		Iterator/*<DiscoveryServiceHandler>*/ it = discoveryServices.iterator();
		String requestURL = req.getRequestURL().toString(); 
		DiscoveryServiceHandler defaultHandler = null;
		
		while (it.hasNext()) {
			DiscoveryServiceHandler handler = (DiscoveryServiceHandler) it.next();
			
			if (requestURL.matches(handler.getLocation())) {
				return handler;
			}
			if (defaultHandler == null || handler.isDefault()) {
				defaultHandler = handler;
			}
		}
		log.warn("Could not find Discovery service Handler for " + requestURL);
		return defaultHandler;
	}


	
}
