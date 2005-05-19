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

public class RegExAttributeDefinition extends SimpleBaseAttributeDefinition implements AttributeDefinitionPlugIn {

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

		// Resolve all dependencies to arrive at the source values (unformatted)
		Collection results = resolveDependencies(attribute, principal, requester, depends);

		Iterator resultsIt = results.iterator();

		while (resultsIt.hasNext()) {
			String value = getString(resultsIt.next());
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
