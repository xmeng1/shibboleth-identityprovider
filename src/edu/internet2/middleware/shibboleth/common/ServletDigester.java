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

package edu.internet2.middleware.shibboleth.common;

import java.io.InputStream;
import java.util.Enumeration;
import java.util.Properties;
import java.util.StringTokenizer;

import javax.servlet.ServletContext;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.apache.commons.digester.Digester;
import org.apache.log4j.Logger;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.XMLReader;

/**
 * This class is a jakarta Digester style parser that will pull schemas from /WEB-INF/schemas, if they 
 * exist.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class ServletDigester extends Digester {

	private static Logger log =
		Logger.getLogger(ServletDigester.class.getName());
	private ServletContext context;
	public ServletDigester() {
		super();
		configure();
	}

	public ServletDigester(ServletContext context) {
		super();
		super.setErrorHandler(new PassThruErrorHandler());
		this.context = context;

	}

	public ServletDigester(SAXParser parser) {
		super(parser);
		super.setErrorHandler(new PassThruErrorHandler());
		configure();
	}

	public ServletDigester(XMLReader reader) {
		super(reader);
		super.setErrorHandler(new PassThruErrorHandler());
		configure();
	}

	/**
	 * @see org.xml.sax.EntityResolver#resolveEntity(String, String)
	 */
	public InputSource resolveEntity(String publicId, String systemId)
		throws SAXException {
		log.debug("Resolving entity for System ID: " + systemId);
		if (context != null && systemId != null) {
			StringTokenizer tokenString = new StringTokenizer(systemId, "/");
			String xsdFile = "";
			while (tokenString.hasMoreTokens()) {
				xsdFile = tokenString.nextToken();
			}
			if (xsdFile.endsWith(".xsd")) {
				InputStream stream =
					context.getResourceAsStream(
						"/WEB-INF/classes/schemas/" + xsdFile);
				if (stream != null) {
					return new InputSource(stream);
				}
			}
		}
		return null;

	}

	/**
	* Return the SAXParser we will use to parse the input stream.  If there
	* is a problem creating the parser, return <code>null</code>.
	*/
	public SAXParser getParser() {

		// Return the parser we already created (if any)
		if (parser != null) {
			return (parser);
		}

		// Create and return a new parser
		synchronized (this) {
			try {
				if (factory == null) {
					factory = SAXParserFactory.newInstance();
				}
				factory.setNamespaceAware(namespaceAware);
				factory.setValidating(validating);
				if (validating) {
					factory.setFeature(
						"http://xml.org/sax/features/namespaces",
						true);
					factory.setFeature(
						"http://xml.org/sax/features/validation",
						true);
					factory.setFeature(
						"http://apache.org/xml/features/validation/schema",
						true);
					factory.setFeature(
						"http://apache.org/xml/features/validation/schema-full-checking",
						true);
				}
				parser = factory.newSAXParser();
				if (validating) {

					Properties schemaProps = new Properties();
					schemaProps.load(
						context.getResourceAsStream(
							"/WEB-INF/conf/schemas.properties"));
					String schemaLocations = "";
					Enumeration schemas = schemaProps.propertyNames();
					while (schemas.hasMoreElements()) {
						String ns = (String) schemas.nextElement();
						schemaLocations += ns
							+ " "
							+ schemaProps.getProperty(ns)
							+ " ";
					}
					log.debug(
						"Overriding schema locations for the following namespace: "
							+ schemaLocations);
					parser.setProperty(
						"http://apache.org/xml/properties/schema/external-schemaLocation",
						schemaLocations);
				}
				return (parser);
			} catch (Exception e) {
				log.error("Error during Digester initialization", e);
				return (null);
			}
		}

	}

	/**
	* Sax <code>ErrorHandler</code> that passes all errors up as new 
	* exceptions.
	*/

	public class PassThruErrorHandler implements ErrorHandler {

		/**
		 * @see org.xml.sax.ErrorHandler#error(SAXParseException)
		 */
		public void error(SAXParseException arg0) throws SAXException {
			throw new SAXException("Error parsing xml file: " + arg0);
		}

		/**
		 * @see org.xml.sax.ErrorHandler#fatalError(SAXParseException)
		 */
		public void fatalError(SAXParseException arg0) throws SAXException {
			throw new SAXException("Error parsing xml file: " + arg0);
		}

		/**
		 * @see org.xml.sax.ErrorHandler#warning(SAXParseException)
		 */
		public void warning(SAXParseException arg0) throws SAXException {
			throw new SAXException("Error parsing xml file: " + arg0);
		}

	}
}
