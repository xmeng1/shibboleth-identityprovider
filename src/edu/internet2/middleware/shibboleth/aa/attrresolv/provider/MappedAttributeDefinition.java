/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
 * provided with the distribution, if any, must include the following acknowledgment: "This product includes software
 * developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu>Internet2 Project.
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

/*
 * Contributed by SunGard SCT.
 */

package edu.internet2.middleware.shibboleth.aa.attrresolv.provider;

import java.security.Principal;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugInException;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttribute;

/**
 * The MappedAttributeDefinition allows an enumeration of mappings between the source attribute values received from a
 * data connector and the values that are returned. The enumeration is essentially a many-to-many mapping in the general
 * case, one-to-one being a very specific but plausible case. The mapping is specified using a series of
 * &lt;ValueMap&gt; elements, each containing a [key set -> value] element. Thus each &lt;ValueMap&gt; is a many-to-one
 * mapping, but since the elements in the keyset are allowed to re-appear in a subsequent &lt;ValueMap&gt;, it becomes a
 * many-to-many mapping. For instance, consider a sample mapping of Luminis Role to an eduPersonAffiliation. Luminis
 * roles are arbitrary whereas eduPersonAffiliation has a constrained set of values, namely affiliate, alum, employee,
 * faculty, student, staff and member. A potential mapping may look as follows:
 * 
 * <pre>
 * 
 *  
 *        &lt;ValueMap value=&quot;affiliate&quot;  keyset=&quot;guest, prospect[a-z ]*, friends&quot;                        /&gt;
 *        &lt;ValueMap value=&quot;alum&quot;       keyset=&quot;alum, alumni&quot;                                           /&gt;
 *        &lt;ValueMap value=&quot;employee&quot;   keyset=&quot;employee&quot;                                               /&gt;
 *        &lt;ValueMap value=&quot;faculty&quot;    keyset=&quot;faculty&quot;                                                /&gt;
 *        &lt;ValueMap value=&quot;member&quot;     keyset=&quot;student, faculty, admin[a-z ]*, [a-z ]*admin, employee&quot; /&gt;
 *        &lt;ValueMap value=&quot;staff&quot;      keyset=&quot;admin[a-z ]*, [a-z ]*admin&quot;                             /&gt;
 *        &lt;ValueMap value=&quot;student&quot;    keyset=&quot;student&quot;                                                /&gt;
 *   
 *  
 * </pre>
 * 
 * This many-to-many mapping will result in a Luminis role of 'student' to imply eduPersonAffiliation values of [member,
 * student] and a Luminis role of admin to imply eduPersonAffiliation value of [member, staff]. The separator used in
 * specifying the keyset can be specified in the &lt;ValueMap&gt; itself and defaults to ",". Leading or trailing spaces
 * in keys are ignored. As illustrated by the above example, the keyset can contain regular expressions against which
 * the source values of the attributes may be matched to arrive at the value mapping. To allow special characters that
 * have special significance as regular expressions (such as <code>*</code>) to appear in the keyset, an attribute
 * 'regex' can be set to false, thus implying that all keys in the keyset should be literally matched. The match can be
 * specified to be case insensitive by setting 'ignoreCase' attribute to true. Since one attribute value can have
 * multiple mappings, and the ValueMap elements are unordered, specifing a catch-all mapping, such as: &lt;ValueMap
 * value="member" keyset="[a-z]*" /&gt; is sure to match every value, irrespective of whether another match was found
 * for the attribute. To allow such a catch-all specification, an attribute 'defaultValue' can be set to the 'catch-all'
 * value. If 'defaultValue' is set to a special value of ampersand (&amp;), the original attribute value itself is added
 * to the attribute. The algorithm for this implementation is the following: We take the [keyset -> value]* mappings
 * specified in the MappedAttributeDefinition (which is perhaps easier to specify) and reverse it to [key -> value set]*
 * mappings internally. These mappings are stored as HashMaps, one HashMap for regex keys and another for non-regex
 * keys. Every attribute value to be resolved is looked up in both these HashMaps and all matching values in the value
 * set is added in lieu of the attribute value to be resolved. If no mapping is found, we use the defaultValue (if
 * specified).
 * 
 * @author <a href="mailto:vgoenka@sungardsct.com">Vishal Goenka </a>
 */

public class MappedAttributeDefinition extends SimpleBaseAttributeDefinition implements AttributeDefinitionPlugIn {

	private static Logger log = Logger.getLogger(MappedAttributeDefinition.class.getName());

	// [simple-key -> mapped value set], where simple-key is not a regular expression
	private HashMap simpleValueMap;

	// [regex-key -> mapped value set], where regex-key is a regular expression
	private HashMap regexValueMap;

	// Should we ignore case when matching against simple or regex keys
	private boolean ignoreCase = false;

	// Default value, if no other value mapping is found
	private String defaultValue;

	// Does the keyset contain regular expressions or simply value strings?
	private boolean regexExpected = false;

	// A pattern that describes a word (without any white space or special characters) This is used to separate 'simple'
	// keys from 'regex' keys when the ValueMap is parsed.
	private Pattern word;

	public MappedAttributeDefinition(Element e) throws ResolutionPlugInException {

		super(e);

		// Does the keyset contain regular expressions or simply value strings?
		regexExpected = Boolean.valueOf(e.getAttribute("regex")).booleanValue();

		// Is the keyset case sensitive
		ignoreCase = Boolean.valueOf(e.getAttribute("ignoreCase")).booleanValue();

		defaultValue = e.getAttribute("defaultValue");

		// Initialize maps to contain [keyset -> value] mappings
		initializeValueMaps();

		NodeList valueMaps = e.getElementsByTagName("ValueMap");
		int count = valueMaps.getLength();
		for (int i = 0; i < count; i++) {
			Element valueMap = (Element) valueMaps.item(i);
			// Parse each ValueMap and initialize the internal data structures
			parseValueMap(valueMap);
		}
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn#resolve(
	 *      edu.internet2.middleware.shibboleth.aa.attrresolv.ArpAttribute, java.security.Principal, java.lang.String,
	 *      edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies)
	 */
	public void resolve(ResolverAttribute attribute, Principal principal, String requester, Dependencies depends)
			throws ResolutionPlugInException {

		// Resolve all dependencies to arrive at the source values (unformatted)
		Collection results = resolveDependencies(attribute, principal, requester, depends);

		Iterator resultsIt = results.iterator();

		// Create string for debugging output
		StringBuffer debugBuffer = new StringBuffer();

		while (resultsIt.hasNext()) {
			// Read the source value (prior to mapping)
			String valueExactCase = getString(resultsIt.next());
			String value = valueExactCase;
			boolean mapped = false;

			if (log.isDebugEnabled()) debugBuffer.append("[").append(value).append(" --> ");

			// The source is converted to lowercase for matching ... the mapped value is returned in 'exact case'
			if (ignoreCase) value = value.toLowerCase();

			// First check if there are value mappings based on exact-match rather than regex matches
			Set simpleMappedValues = (Set) simpleValueMap.get(value);
			if (simpleMappedValues != null) {
				// Add all mapped values to the attribute
				for (Iterator it = simpleMappedValues.iterator(); it.hasNext();) {
					String simpleMappedValue = (String) it.next();
					attribute.addValue(simpleMappedValue);
					mapped = true;
					if (log.isDebugEnabled()) debugBuffer.append(simpleMappedValue).append(", ");
				}
			}

			// If we are expecting the keyset to contain regular expressions, the matching process is exhaustive!
			try {
				if (regexExpected) {
					// Check all entries in the hashmap for a regex match between the source value and the regex-key
					for (Iterator it = regexValueMap.entrySet().iterator(); it.hasNext();) {
						Map.Entry entry = (Map.Entry) it.next();
						Pattern regexKey = (Pattern) entry.getKey();
						if (regexKey.matcher(value).matches()) {
							// Add all values
							Set regexMappedValues = (Set) entry.getValue();
							for (Iterator vit = regexMappedValues.iterator(); vit.hasNext();) {
								String regexMappedValue = (String) vit.next();
								attribute.addValue(regexMappedValue);
								mapped = true;
								if (log.isDebugEnabled()) debugBuffer.append(regexMappedValue).append(", ");
							}
						}
					}
				}
			} catch (Exception e) {
				// Any exception during the regex match only skips the attribute value being matched ...
				log.error("Attribute value for (" + getId() + ") --> (" + value
						+ ") failed during regex processing with exception: " + e.getMessage());
			}

			// Was there was no mapping found for this value?
			if (!mapped && (defaultValue != null) && (defaultValue.length() > 0)) {
				if (defaultValue.equals("&")) {
					attribute.addValue(valueExactCase);
					if (log.isDebugEnabled()) debugBuffer.append(valueExactCase);
				} else {
					attribute.addValue(defaultValue);
					if (log.isDebugEnabled()) debugBuffer.append(defaultValue);
				}
			}

			if (log.isDebugEnabled()) debugBuffer.append("] ");
		}
		attribute.setResolved();
		if (log.isDebugEnabled())
			log.debug("Attribute values upon mapping for (" + getId() + "): " + debugBuffer.toString());
	}

	/**
	 * Helper method ... allocates hashmaps etc.
	 */
	private void initializeValueMaps() {

		simpleValueMap = new HashMap();
		regexValueMap = new HashMap();
		word = Pattern.compile("^\\w+$");
	}

	/**
	 * This method reads the [value --> keyset] and reverses the mapping to [key -> value set]* for easier attribute
	 * resolution. Each key in the keyset is evaluated for whether it is a regex or not, and is stored in the
	 * regexValueMap or simpleValueMap based on whether the key contains any non-word characters.
	 */
	private void parseValueMap(Element element) throws ResolutionPlugInException {

		String value = element.getAttribute("value");
		String keyset = element.getAttribute("keyset");
		String separator = element.getAttribute("separator");

		if ((value == null) || ("".equals(value)) || (keyset == null) || ("".equals(keyset))) {
			String error = "value and keyset attributes MUST both be non-empty in the ValueMap element for attribute ("
					+ getId() + ")";
			log.error(error);
			throw new ResolutionPlugInException(error);
		}

		// The separator for entries in the keyset
		if ((separator == null) || ("".equals(separator))) separator = ",";

		StringTokenizer st = new StringTokenizer(keyset, separator);
		while (st.hasMoreTokens()) {
			// trim to remove spaces that are used immediately after a separator in the keyset, even when space
			// otherwise is
			// not a separator
			String key = st.nextToken().trim();

			// If ignoreCase, values will also be converted to lowercase before the match is attempted
			if (ignoreCase) key = key.toLowerCase();

			// Lets assume that the key is a simple String and therefore the valueMap to store the mapping is
			// simpleValueMap
			Object keyObject = key;
			HashMap valueMap = simpleValueMap;

			// If we are expecting regex and this is one, add it to regex value map, else add it to simpleValueMap
			if (regexExpected && !word.matcher(key).matches()) {
				keyObject = Pattern.compile(key);
				valueMap = regexValueMap;
			}

			HashSet valueSet = (HashSet) valueMap.get(keyObject);
			if (valueSet == null) {
				valueSet = new HashSet();
				valueMap.put(keyObject, valueSet);
			}
			valueSet.add(value);
		}
	}
}
