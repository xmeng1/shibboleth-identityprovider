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

package edu.internet2.middleware.shibboleth.idp.provider;

import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERString;
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
	private static final String CN_OID = "2.5.4.3";
	private HashSet<String> locations = new HashSet<String>();

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
					log.error("The <Location/> element inside the <ProtocolHandler/> element must "
							+ "contain a URI or regular expressions.");
					throw new ShibbolethConfigurationException("Unable to load ProtocolHandler.");
				}
				this.locations.add(rawURI);

			} else {
				log.error("The <Location/> element inside the <ProtocolHandler/> element must contain a "
						+ "URI or regular expression.");
				throw new ShibbolethConfigurationException("Unable to load ProtocolHandler.");
			}
		}
	}

	/*
	 * @see edu.internet2.middleware.shibboleth.idp.IdPProtocolHandler#getLocations()
	 */
	public String[] getLocations() {

		return (String[]) locations.toArray(new String[0]);
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
					log.debug("No DN components.");
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
									&& ((DERSequence) grandChild).getObjectAt(1).getDERObject() instanceof DERString) {
								cn = ((DERString) ((DERSequence) grandChild).getObjectAt(1).getDERObject()).getString();
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

	protected static String[] getCredentialNames(X509Certificate cert) {

		ArrayList<String> names = new ArrayList<String>();
		names.add(cert.getSubjectX500Principal().getName(X500Principal.RFC2253));
		try {
			Collection altNames = cert.getSubjectAlternativeNames();
			if (altNames != null) {
				for (Iterator nameIterator = altNames.iterator(); nameIterator.hasNext();) {
					List altName = (List) nameIterator.next();
					if (altName.get(0).equals(new Integer(2)) && altName.get(1) instanceof String) { // 2 is DNS
						names.add((String) altName.get(1));
					} else if (altName.get(0).equals(new Integer(6)) && altName.get(1) instanceof String) { // 6 is URI
						names.add((String) altName.get(1));
					}
				}
			}
		} catch (CertificateParsingException e1) {
			log.error("Encountered an problem trying to extract Subject Alternate "
					+ "Name from supplied certificate: " + e1);
		}
		names.add(getHostNameFromDN(cert.getSubjectX500Principal()));
		return (String[]) names.toArray(new String[1]);
	}
}