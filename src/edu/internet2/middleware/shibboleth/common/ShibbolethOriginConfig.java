/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation
 * for Advanced Internet Development, Inc. All rights reserved
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
 * <http://www.ucaid.edu> Internet2 Project. Alternately, this acknowledegement
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
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package edu.internet2.middleware.shibboleth.common;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Enumeration;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.opensaml.SAMLAuthenticationStatement;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.hs.HSConfigurationException;

/**
 * @author Walter Hoehn
 *
 */
public class ShibbolethOriginConfig {
	
	private static Logger log = Logger.getLogger(ShibbolethOriginConfig.class.getName());
	protected Properties properties;
	
	public ShibbolethOriginConfig(Element config) throws HSConfigurationException {
//		Set defaults
			  Properties defaultProps = new Properties();
			  defaultProps.setProperty("edu.internet2.middleware.shibboleth.hs.HandleServlet.username", "REMOTE_USER");
			  defaultProps.setProperty("edu.internet2.middleware.shibboleth.hs.HandleServlet.maxThreads", "5");
			  defaultProps.setProperty(
				  "edu.internet2.middleware.shibboleth.hs.HandleRepository.implementation",
				  "edu.internet2.middleware.shibboleth.hs.provider.MemoryHandleRepository");
			  defaultProps.setProperty("edu.internet2.middleware.shibboleth.hs.BaseHandleRepository.handleTTL", "1800000");
			  defaultProps.setProperty(
				  "edu.internet2.middleware.shibboleth.hs.provider.CryptoHandleRepository.keyStorePath",
				  "/conf/handle.jks");
			  defaultProps.setProperty("edu.internet2.middleware.shibboleth.audiences", "urn:mace:inqueue");
			  defaultProps.setProperty(
				  "edu.internet2.middleware.shibboleth.hs.HandleServlet.authMethod",
				  SAMLAuthenticationStatement.AuthenticationMethod_Unspecified);

			  //Load from file
			  properties = new Properties(defaultProps);
			  //TODO fix this!!!
			  String propertiesFileLocation = "foo";//= getInitParameter("OriginPropertiesFile");
			  
			  if (propertiesFileLocation == null) {
				  propertiesFileLocation = "/conf/origin.properties";
			  }
			  try {
				  log.debug("Loading Configuration from (" + propertiesFileLocation + ").");
				  properties.load(new ShibResource(propertiesFileLocation, this.getClass()).getInputStream());

				  //Make sure we have all required parameters
				  StringBuffer missingProperties = new StringBuffer();
				  String[] requiredProperties =
					  {
						  "edu.internet2.middleware.shibboleth.hs.HandleServlet.issuer",
						  "edu.internet2.middleware.shibboleth.hs.HandleServlet.siteName",
						  "edu.internet2.middleware.shibboleth.hs.HandleServlet.AAUrl",
						  "edu.internet2.middleware.shibboleth.hs.HandleServlet.keyStorePath",
						  "edu.internet2.middleware.shibboleth.hs.HandleServlet.keyStorePassword",
						  "edu.internet2.middleware.shibboleth.hs.HandleServlet.keyStoreKeyAlias",
						  "edu.internet2.middleware.shibboleth.hs.HandleServlet.keyStoreKeyPassword",
						  "edu.internet2.middleware.shibboleth.hs.HandleServlet.authMethod",
						  "edu.internet2.middleware.shibboleth.audiences" };

				  for (int i = 0; i < requiredProperties.length; i++) {
					  if (properties.getProperty(requiredProperties[i]) == null) {
						  missingProperties.append("\"");
						  missingProperties.append(requiredProperties[i]);
						  missingProperties.append("\" ");
					  }
				  }
				  if (missingProperties.length() > 0) {
					  log.error(
						  "Missing configuration data.  The following configuration properites have not been set: "
							  + missingProperties.toString());
					  throw new HSConfigurationException("Missing configuration data.");
				  }

			  } catch (IOException e) {
				  log.error("Could not load HS servlet configuration: " + e);
				  throw new HSConfigurationException("Could not load HS servlet configuration.");
			  }

			  if (log.isDebugEnabled()) {
				  ByteArrayOutputStream debugStream = new ByteArrayOutputStream();
				  PrintStream debugPrinter = new PrintStream(debugStream);
				  properties.list(debugPrinter);
				  log.debug(
					  "Runtime configuration parameters: " + System.getProperty("line.separator") + debugStream.toString());
				  try {
					  debugStream.close();
				  } catch (IOException e) {
					  log.error("Encountered a problem cleaning up resources: could not close debug stream.");
				  }
			  }
		
			  //Be nice and trim "extra" whitespace from config properties
			  Enumeration propNames = properties.propertyNames();
			  while (propNames.hasMoreElements()) {
				  String propName = (String) propNames.nextElement();
				  if (properties.getProperty(propName, "").matches(".+\\s$")) {
					  log.debug(
						  "The configuration property ("
							  + propName
							  + ") contains trailing whitespace.  Trimming... ");
					  properties.setProperty(propName, properties.getProperty(propName).trim());
				  }
			  }

	}
	
	public String getConfigProperty(String key) {
		return properties.getProperty(key);
	}

}
