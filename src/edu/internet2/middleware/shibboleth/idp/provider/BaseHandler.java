/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
 * provided with the distribution, if any, must include the following acknowledgment: "This product includes software
 * developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu> Internet2 Project.
 * Alternately, this acknowledegement may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear. Neither the name of Shibboleth nor the names of its contributors, nor Internet2, nor
 * the University Corporation for Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote
 * products derived from this software without specific prior written permission. For written permission, please contact
 * shibboleth@shibboleth.org Products derived from this software may not be called Shibboleth, Internet2, UCAID, or the
 * University Corporation for Advanced Internet Development, nor may Shibboleth appear in their name, without prior
 * written permission of the University Corporation for Advanced Internet Development. THIS SOFTWARE IS PROVIDED BY THE
 * COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE
 * DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. IN NO
 * EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC.
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.shibboleth.idp.provider;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.idp.IdPConfig;
import edu.internet2.middleware.shibboleth.idp.IdPProtocolHandler;

/**
 * Functionality common to all <code>IdPProtocolHandler</code> implementation.
 * 
 * @author Walter Hoehn
 */
public abstract class BaseHandler implements IdPProtocolHandler {

	private static Logger log = Logger.getLogger(BaseHandler.class.getName());
	private HashSet locations = new HashSet();
	private static final String CN_OID = "2.5.4.3";

	/**
	 * Required DOM-based constructor.
	 */
	public BaseHandler(Element config) throws ShibbolethConfigurationException {

		// Make sure we have at least one location
		NodeList locations = config.getElementsByTagNameNS(IdPConfig.configNameSpace, "Location");
		if (locations.getLength() < 1) {
			log.error("The <ProtocolHandler/> element must contain at least one <Location/> element.");
			throw new ShibbolethConfigurationException("Unable to load ProtocolHandler.");
		}

		// Parse the locations
		for (int i = 0; i < locations.getLength(); i++) {
			Node tnode = ((Element) locations.item(i)).getFirstChild();
			if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
				String rawURI = tnode.getNodeValue();

				if (rawURI == null || rawURI.equals("")) {
					log.error("The <Location/> element inside the <ProtocolHandler/> element must contain a URI.");
					throw new ShibbolethConfigurationException("Unable to load ProtocolHandler.");
				}

				try {
					URI location = new URI(rawURI);
					this.locations.add(location);
				} catch (URISyntaxException e) {
					log.error("The <Location/> element inside the <ProtocolHandler/> element contains "
							+ "an improperly formatted URI: " + e);
					throw new ShibbolethConfigurationException("Unable to load ProtocolHandler.");
				}

			} else {
				log.error("The <Location/> element inside the <ProtocolHandler/> element must contain a URI.");
				throw new ShibbolethConfigurationException("Unable to load ProtocolHandler.");
			}
		}
	}

	/*
	 * @see edu.internet2.middleware.shibboleth.idp.IdPProtocolHandler#getLocations()
	 */
	public URI[] getLocations() {

		return (URI[]) locations.toArray(new URI[0]);
	}

	protected static String getHostNameFromDN(X500Principal dn) {

		// Parse the ASN.1 representation of the dn and grab the last CN component that we find
		// We used to do this with the dn string, but the JDK's default parsing caused problems with some DNs

		try {
			ASN1InputStream asn1Stream = new ASN1InputStream(dn.getEncoded());
			DERObject parent = asn1Stream.readObject();

			if (!(parent instanceof DERSequence)) {
				log.error("Unable to extract host name name from certificate subject DN: incorrect ASN.1 encoding.");
				return null;
			}

			String cn = null;
			for (int i = 0; i < ((DERSequence) parent).size(); i++) {
				DERObject dnComponent = ((DERSequence) parent).getObjectAt(i).getDERObject();
				if (!(dnComponent instanceof DERSet)) {
					continue;
				}

				// Each DN component is a set
				for (int j = 0; j < ((DERSet) dnComponent).size(); j++) {
					DERObject grandChild = ((DERSet) dnComponent).getObjectAt(j).getDERObject();

					if (((DERSequence) grandChild).getObjectAt(0) != null
							&& ((DERSequence) grandChild).getObjectAt(0).getDERObject() instanceof DERObjectIdentifier) {
						DERObjectIdentifier componentId = (DERObjectIdentifier) ((DERSequence) grandChild).getObjectAt(
								0).getDERObject();

						if (CN_OID.equals(componentId.getId())) {
							// OK, this dn component is actually a cn attribute
							if (((DERSequence) grandChild).getObjectAt(1) != null
									&& ((DERSequence) grandChild).getObjectAt(1).getDERObject() instanceof DERPrintableString) {
								cn = ((DERPrintableString) ((DERSequence) grandChild).getObjectAt(1).getDERObject())
										.getString();
							}
						}
					}
				}
			}
			asn1Stream.close();
			return cn;

		} catch (IOException e) {
			log.error("Unable to extract host name name from certificate subject DN: ASN.1 parsing failed: " + e);
			return null;
		}
	}
}