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

/*
 * Contributed by SunGard SCT.
 */

package edu.internet2.middleware.shibboleth.aa.attrresolv.provider;

import java.security.Principal;
import java.util.Collection;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugInException;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttribute;

/**
 * The RegExAttributeDefinition allows regular expression based replacements on attribute values, using the regex syntax
 * allowed by java.util.regex.Pattern. Capturing groups can be specified in the regex string using parenthesis and in
 * the replacement string using $i, where i = 0-9. Case-insensitive matches can be specified using the 'ignoreCase'
 * attribute set to true. No other flags allowed by java.util.regex.Pattern are deemed useful and hence not supported
 * yet, but are easy to add if needed.
 * 
 * @author <a href="mailto:vgoenka@sungardsct.com">Vishal Goenka </a>
 */

/*
 * An alternate way to implement a regex replacement would be to write a special value handler, pre-configured with the
 * regex pattern and replacement string. Since ValueHandlers are initialized using the default no-args constructor,
 * their re-usability based on configuration parameters is limited. The RegExAttributeDefinition therefore builds on the
 * SimpleAttributeDefinition by allowing specification of regular expression parameters as configuration values instead.
 * A value handler may also be specified, if needed. The value handler will see the 'formatted' value after the regular
 * expression substitution.
 */

public class RegExAttributeDefinition extends BaseAttributeDefinition implements AttributeDefinitionPlugIn {

	private static Logger log = Logger.getLogger(RegExAttributeDefinition.class.getName());

	// The pattern to match the source attribute value with
	private Pattern pattern;

	// Unless partialMatch is set to true (defaults to false), the pattern MUST match the full value
	private boolean partialMatch = false;

	// The replacement string to replace the matched groups in the pattern with, must be non-empty unless partialMatch
	// is set to true
	private String replacement;

	public RegExAttributeDefinition(Element e) throws ResolutionPlugInException {

		super(e);

		try {
			String regex = e.getAttribute("regex");
			if ((regex == null) || ("".equals(regex)))
				throw new ResolutionPlugInException("(" + getId()
						+ ") 'regex' is a required attribute for RegExAttributeDefinition");

			partialMatch = Boolean.valueOf(e.getAttribute("partialMatch")).booleanValue();

			replacement = e.getAttribute("replacement");
			if (!partialMatch && ((replacement == null) || ("".equals(replacement))))
				throw new ResolutionPlugInException(
						"("
								+ getId()
								+ ") 'replacement' MUST NOT be empty, unless 'partialMatch' is true for RegExAttributeDefinition");

			int flags = 0;
			boolean ignoreCase = Boolean.valueOf(e.getAttribute("ignoreCase")).booleanValue();
			if (ignoreCase) flags = Pattern.CASE_INSENSITIVE;

			pattern = Pattern.compile(regex, flags);

			if (log.isDebugEnabled())
				log.debug("RegEx Pattern = " + pattern.pattern() + ", Replacement = " + replacement + " for ("
						+ getId() + ")");
		} catch (ResolutionPlugInException ex) {
			// To ensure that exceptions thrown in the constructor are logged!
			log.error(ex.getMessage());
			throw ex;
		}
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn#resolve(edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttribute,
	 *      java.security.Principal, java.lang.String, java.lang.String,
	 *      edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies)
	 */
	public void resolve(ResolverAttribute attribute, Principal principal, String requester, String responder,
			Dependencies depends) throws ResolutionPlugInException {

		super.resolve(attribute, principal, requester, responder, depends);

		// Resolve all dependencies to arrive at the source values (unformatted)
		Collection results = getValuesFromAllDeps(attribute, principal, requester, depends);

		Iterator resultsIt = results.iterator();

		while (resultsIt.hasNext()) {
			String value = convertToString(resultsIt.next());
			Matcher m = pattern.matcher(value);
			try {
				if (partialMatch || m.matches()) attribute.addValue(m.replaceAll(replacement));
				else log.debug("Attribute value for (" + getId() + ") --> (" + value + ") did not match regex pattern");
			} catch (Exception e) {
				// We simply log an error for values that give errors during formatting rather than abandoning the whole
				// process
				log.error("Attribute value for (" + getId() + ") --> (" + value
						+ ") failed during regex processing with exception: " + e.getMessage());
			}
		}
		attribute.setResolved();
	}
}