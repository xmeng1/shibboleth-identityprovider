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

package edu.internet2.middleware.shibboleth.common;

import java.util.ArrayList;
import java.util.Iterator;

import javax.servlet.http.HttpServlet;

import org.apache.log4j.Logger;
import org.opensaml.artifact.Artifact;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.metadata.Metadata;
import edu.internet2.middleware.shibboleth.metadata.MetadataException;
import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;

/**
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public class TargetFederationComponent extends HttpServlet implements Metadata {

	private static Logger	log			= Logger.getLogger(TargetFederationComponent.class.getName());

	private ArrayList		fedMetadata	= new ArrayList();

	protected void addFederationProvider(Element element) {
		log.debug("Found Federation Provider configuration element.");
		if (!element.getTagName().equals("FederationProvider")) {
			log.error("Error while attemtping to load Federation Provider.  Malformed provider specificaion.");
			return;
		}

		try {
			fedMetadata.add(FederationProviderFactory.loadProvider(element));
		} catch (MetadataException e) {
			log.error("Unable to load Federation Provider.  Skipping...");
		}
	}

	protected int providerCount() {
		return fedMetadata.size();
	}

	public EntityDescriptor lookup(String providerId) {

		Iterator iterator = fedMetadata.iterator();
		while (iterator.hasNext()) {
			EntityDescriptor provider = ((Metadata) iterator.next()).lookup(providerId);
			if (provider != null) {
				return provider;
			}
		}
		return null;
	}

    public EntityDescriptor lookup(Artifact artifact) {
        Iterator iterator = fedMetadata.iterator();
        while (iterator.hasNext()) {
            EntityDescriptor provider = ((Metadata) iterator.next()).lookup(artifact);
            if (provider != null) {
                return provider;
            }
        }
        return null;
    }
}

class FederationProviderFactory {

	private static Logger	log	= Logger.getLogger(FederationProviderFactory.class.getName());

	public static Metadata loadProvider(Element e) throws MetadataException {

		String className = e.getAttribute("type");
		if (className == null || className.equals("")) {
			log.error("Federation Provider requires specification of the attribute \"type\".");
			throw new MetadataException("Failed to initialize Federation Provider.");
		} else {
			try {
				Class[] params = {Class.forName("org.w3c.dom.Element"),};
				return (Metadata) Class.forName(className).getConstructor(params).newInstance(new Object[]{e});
			} catch (Exception loaderException) {
				log.error("Failed to load Federation Provider implementation class: " + loaderException);
                Throwable cause = loaderException.getCause();
                while (cause != null) {
					log.error("caused by: " + cause);
                    cause = cause.getCause();
                }
				throw new MetadataException("Failed to initialize Federation Provider.");
			}
		}
	}
}
