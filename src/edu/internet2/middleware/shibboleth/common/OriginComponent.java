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

import java.io.IOException;
import java.io.InputStream;
import java.util.StringTokenizer;

import javax.servlet.http.HttpServlet;

import org.apache.log4j.Logger;
import org.apache.xerces.parsers.DOMParser;
import org.xml.sax.EntityResolver;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.w3c.dom.Document;

/**
 * @author Walter Hoehn
 */
public abstract class OriginComponent extends HttpServlet {

	private static Logger log = Logger.getLogger(OriginComponent.class.getName());
        private static Document originConfig = null;

        /* synchronized to make sure only one thread attempts to parse the config file */
        protected synchronized Document getOriginConfig () throws ShibbolethConfigurationException
        {
            if (originConfig != null)
            {
                return originConfig;
            }

            DOMParser parser = new DOMParser();

            try {
                parser.setFeature("http://xml.org/sax/features/validation", true);
                parser.setFeature("http://apache.org/xml/features/validation/schema", true);

                parser.setEntityResolver(
                        new EntityResolver() {
                            public InputSource resolveEntity(String publicId, String systemId) throws SAXException {
                                log.debug("Resolving entity for System ID: " + systemId);
                                if (systemId != null) {
                                    StringTokenizer tokenString = new StringTokenizer(systemId, "/");
                                    String xsdFile = "";
                                    while (tokenString.hasMoreTokens()) {
                                        xsdFile = tokenString.nextToken();
                                    }
                                    if (xsdFile.endsWith(".xsd")) {
                                        InputStream stream;
                                        try {
                                            stream = new ShibResource("/schemas/" + xsdFile, this.getClass()).getInputStream();
                                        } catch (IOException ioe) {
                                            log.error("Error loading schema: " + xsdFile + ": " + ioe);
                                            return null;
                                        }
                                        if (stream != null) {
                                            return new InputSource(stream);
                                        }
                                    }
                                }
                                return null;
                            }
                        });

                parser.setErrorHandler(new ErrorHandler() {
                    public void error(SAXParseException arg0) throws SAXException {
                        throw new SAXException("Error parsing xml file: " + arg0);
                    }
                    public void fatalError(SAXParseException arg0) throws SAXException {
                        throw new SAXException("Error parsing xml file: " + arg0);
                    }
                    public void warning(SAXParseException arg0) throws SAXException {
                        throw new SAXException("Error parsing xml file: " + arg0);
                    }
                });

            } catch (SAXException e) {
                log.error("Unable to setup a workable XML parser: " + e);
                throw new ShibbolethConfigurationException("Unable to setup a workable XML parser.");
            }

            String originConfigFile = getInitParameter("OriginConfigFile");
            if (originConfigFile == null) {
                originConfigFile = "/conf/origin.xml";
            }

            log.debug("Loading Configuration from (" + originConfigFile + ").");

            try {
                parser.parse(new InputSource(new ShibResource(originConfigFile, this.getClass()).getInputStream()));
            } catch (SAXException e) {
                log.error("Error while parsing origin configuration: " + e);
                throw new ShibbolethConfigurationException("Error while parsing origin configuration.");
            } catch (IOException e) {
                log.error("Could not load origin configuration: " + e);
                throw new ShibbolethConfigurationException("Could not load origin configuration.");
            }

            originConfig = parser.getDocument();

            return originConfig;
        }
}
