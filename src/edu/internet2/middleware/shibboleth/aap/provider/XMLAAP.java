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

package edu.internet2.middleware.shibboleth.aap.provider;

import java.io.IOException;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.opensaml.MalformedException;
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
import edu.internet2.middleware.shibboleth.xml.Parser;

/**
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public class XMLAAP extends ResourceWatchdog implements AAP {

	private static Logger	log	= Logger.getLogger(XMLAAP.class.getName());
	private AAP		currentAAP;

	public XMLAAP(Element configuration) throws MalformedException, ResourceNotAvailableException {
		this(configuration.getAttribute("uri"));
	}

	public XMLAAP(String sitesFileLocation) throws MalformedException, ResourceNotAvailableException {
		super(new ShibResource(sitesFileLocation, XMLAAP.class));
		try {
            InputSource src = new InputSource(resource.getInputStream());
            src.setSystemId(resource.getURL().toString());
			Document doc = Parser.loadDom(src,true);
			currentAAP = new XMLAAPProvider(doc.getDocumentElement());
		} catch (IOException e) {
			log.error("Encountered a problem reading AAP source: " + e);
			throw new MalformedException("Unable to read AAP: " + e);
		}
        catch (SAXException e) {
            log.error("Encountered a problem parsing AAP source: " + e);
            throw new MalformedException("Unable to read AAP: " + e);
        }
        catch (SAMLException e) {
            log.error("Encountered a problem processing AAP source: " + e);
            throw new MalformedException("Unable to read AAP: " + e);
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
