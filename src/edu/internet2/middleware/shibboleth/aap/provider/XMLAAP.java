/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the
 * above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution, if any, must include the following acknowledgment: "This product includes
 * software developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu>Internet2
 * Project. Alternately, this acknowledegement may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear. Neither the name of Shibboleth nor the names of its contributors, nor Internet2,
 * nor the University Corporation for Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote
 * products derived from this software without specific prior written permission. For written permission, please
 * contact shibboleth@shibboleth.org Products derived from this software may not be called Shibboleth, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor may Shibboleth appear in their name,
 * without prior written permission of the University Corporation for Advanced Internet Development. THIS SOFTWARE IS
 * PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND
 * NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS
 * WITH LICENSEE. IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY CORPORATION FOR ADVANCED
 * INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.aap.provider;

import java.io.IOException;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.opensaml.SAMLException;
import org.opensaml.XML;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import edu.internet2.middleware.shibboleth.aap.AAP;
import edu.internet2.middleware.shibboleth.aap.AttributeRule;
import edu.internet2.middleware.shibboleth.common.ResourceWatchdog;
import edu.internet2.middleware.shibboleth.common.ResourceWatchdogExecutionException;
import edu.internet2.middleware.shibboleth.common.ShibResource;
import edu.internet2.middleware.shibboleth.common.ShibResource.ResourceNotAvailableException;
import edu.internet2.middleware.shibboleth.metadata.MetadataException;
import edu.internet2.middleware.shibboleth.xml.Parser;

/**
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public class XMLAAP extends ResourceWatchdog implements AAP {

	private static Logger	log	= Logger.getLogger(XMLAAP.class.getName());
	private AAP		currentAAP;

	public XMLAAP(Element configuration) throws MetadataException, ResourceNotAvailableException {
		this(configuration.getAttribute("uri"));
	}

	public XMLAAP(String sitesFileLocation) throws MetadataException, ResourceNotAvailableException {
		super(new ShibResource(sitesFileLocation, XMLAAP.class));
		try {
            InputSource src = new InputSource(resource.getInputStream());
            src.setSystemId(resource.getURL().toString());
			Document doc = Parser.loadDom(src,true);
			currentAAP = new XMLAAP(doc.getDocumentElement());
		} catch (IOException e) {
			log.error("Encountered a problem reading AAP source: " + e);
			throw new MetadataException("Unable to read AAP: " + e);
		}
        catch (SAXException e) {
            log.error("Encountered a problem parsing AAP source: " + e);
            throw new MetadataException("Unable to read AAP: + e");
        }
        catch (SAMLException e) {
            log.error("Encountered a problem processing AAP source: " + e);
            throw new MetadataException("Unable to read AAP: + e");
        }

		//Start checking for AAP updates
		start();

	}

    public boolean anyAttribute() {
        synchronized (currentAAP) {
            return currentAAP.anyAttribute();
        }
    }

    public AttributeRule lookup(String name, String namespace) {
        synchronized (currentAAP) {
            return currentAAP.lookup(name,namespace);
        }
    }

    public AttributeRule lookup(String alias) {
        synchronized (currentAAP) {
            return currentAAP.lookup(alias);
        }
    }

    public Iterator getAttributeRules() {
        synchronized (currentAAP) {
            return currentAAP.getAttributeRules();
        }
    }

	protected void doOnChange() throws ResourceWatchdogExecutionException {
        AAP newAAP = null;
        Document newDoc = null;

		try {
			log.info("Detected a change in the AAP. Reloading from (" + resource.getURL().toString() + ").");
            newAAP = new XMLAAP(XML.parserPool.parse(resource.getInputStream()).getDocumentElement());
        }
        catch (IOException e) {
			log.error("Encountered an error retrieving updated AAP, continuing to use stale copy: " + e);
			return;
		}
        catch (SAXException e) {
            log.error("Encountered an error retrieving updated AAP, continuing to use stale copy: " + e);
            return;
        }
        catch (SAMLException e) {
            log.error("Encountered an error retrieving updated AAP, continuing to use stale copy: " + e);
            return;
        }

		if (newAAP != null) {
			synchronized (currentAAP) {
				currentAAP = newAAP;
			}
		}
	}
}
