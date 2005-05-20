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

import java.lang.reflect.Constructor;
import java.security.Principal;
import java.text.Format;
import java.util.Collection;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugInException;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttribute;

/**
 * The FormattedAttributeDefinition allows attribute values to be formatted using any custom formatter, such as the
 * java.text.MessageFormat, java.text.DateFormat or java.text.NumberFormat etc. It allows the source attribute to be
 * parsed using a specified formatter and the target to formatted using another formatter. Since the formatters for
 * source and target are both passed in as arguments along with the pattern string, a high degree of customization is
 * allowed. A value handler may also be specified, if needed. The value handler will see the 'target' value after the
 * target formatter has completed the value transformation. The 'format' attribute of the Source and Target elements
 * specify the class name of the formatter and MUST be a subclass of java.text.Format. The
 * <code>sourceFormat.parseObject(sourceValue)</code> method is used to convert the source attribute to an Object
 * (say, obj), which is then converted back to a String using the <code>targetFormat.format( obj )</code> method.
 * 
 * @author <a href="mailto:vgoenka@sungardsct.com">Vishal Goenka </a>
 */

public class FormattedAttributeDefinition extends SimpleBaseAttributeDefinition implements AttributeDefinitionPlugIn {

	private static Logger log = Logger.getLogger(FormattedAttributeDefinition.class.getName());

	// The format of Source Attribute
	private Format sourceFormat;

	// The format of Target Attribute
	private Format targetFormat;

	// if source and target formatters are same should we skip formatting? In a few cases, the formatter may still
	// produce
	// a different result so one may still want the formatting, even though the source and target formatters are
	// identical.
	private boolean skipFormatting = false;

	public FormattedAttributeDefinition(Element e) throws ResolutionPlugInException {

		super(e);
		NodeList sources = e.getElementsByTagName("Source");
		NodeList targets = e.getElementsByTagName("Target");

		if ((sources == null) || (sources.getLength() != 1) || (targets == null) || (targets.getLength() != 1)) {
			log
					.error("There MUST be exactly 1 'Source' and 1 'Target' definition for a FormattedAttributeDefinition for ("
							+ getId() + ")");
			throw new ResolutionPlugInException(
					"There MUST be exactly 1 'Source' and 1 'Target' definition for a FormattedAttributeDefinition for ("
							+ getId() + ")");
		}
		Element source = (Element) sources.item(0);
		Element target = (Element) targets.item(0);

		sourceFormat = createFormat(source);
		targetFormat = createFormat(target);

		if (sourceFormat.equals(targetFormat)) {
			String skipIfSameFormat = e.getAttribute("skipIfSameFormat");
			skipFormatting = Boolean.valueOf(skipIfSameFormat).booleanValue();
			if (!skipFormatting) {
				log.warn("Source and Target formats are identical for (" + getId()
						+ "). Set 'skipIfSameFormat=true' on the CustomAttributeDefinition element to skip.");
			} else {
				log.debug("Source and Target formats are identical for (" + getId()
						+ "). Formatting will be skipped since 'skipIfSameFormat=true'");
			}
		}
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn#resolve(edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttribute,
	 *      java.security.Principal, java.lang.String, java.lang.String,
	 *      edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies)
	 */
	public void resolve(ResolverAttribute attribute, Principal principal, String requester, String responder,
			Dependencies depends) throws ResolutionPlugInException {

		standardProcessing(attribute);

		// Resolve all dependencies to arrive at the source values (unformatted)
		Collection results = resolveDependencies(attribute, principal, requester, depends);

		Iterator resultsIt = results.iterator();

		while (resultsIt.hasNext()) {
			String value = getString(resultsIt.next());
			if (skipFormatting) attribute.addValue(value);
			else {
				try {
					Object parsed = sourceFormat.parseObject(value);
					value = targetFormat.format(parsed);
					attribute.addValue(value);
				} catch (Exception e) {
					// We simply log an error for values that give errors during formatting rather than abandoning the
					// whole process
					log.error("Attribute value for (" + getId() + ") --> (" + value
							+ ") failed during format conversion with exception: " + e.getMessage());
				}
			}
		}
		attribute.setResolved();
	}

	/**
	 * Construct the specified formatter, which must be an instance of java.text.Format. It reads the attributes
	 * 'format' and 'pattern' from the specified element, asserts that both are non-null and instantiates the class
	 * specified by 'format' by passing in the 'pattern' to the single String argument constructor.
	 * 
	 * @param element
	 *            the XML element describing the FormatType as defined in the FormattedAttributeDefinition.xsd
	 * @return the initialized formatter, which must be a sub-class of java.text.Format
	 */
	private Format createFormat(Element element) throws ResolutionPlugInException {

		String elementName = element.getTagName();
		String format = element.getAttribute("format");
		String pattern = element.getAttribute("pattern");

		log.debug(getId() + " <" + elementName + " format=\"" + format + "\" pattern=\"" + pattern + "\"/>");

		if ((format == null) || ("".equals(format)) || (pattern == null) || ("".equals(pattern))) {
			String error = elementName + " must have 'format' and 'pattern' attributes specified for (" + getId() + ")";
			log.error(error);
			throw new ResolutionPlugInException(error);
		}
		try {
			Class formatClass = Class.forName(format);
			if (!Format.class.isAssignableFrom(formatClass)) { throw new ResolutionPlugInException("Specified format ("
					+ format + ") MUST be a subclass of java.text.Format"); }
			Constructor formatCons = formatClass.getConstructor(new Class[]{String.class});
			return (Format) formatCons.newInstance(new String[]{pattern});
		} catch (ClassNotFoundException e) {
			String error = "Specified format class (" + format + ") could not be found for (" + getId() + ")";
			log.error(error);
			throw new ResolutionPlugInException(error);
		} catch (Exception e) {
			String error = "Error creating " + elementName + " formatter for (" + getId() + "). Cause: "
					+ e.getMessage();
			log.error(error, e);
			throw new ResolutionPlugInException(error);
		}
	}

}