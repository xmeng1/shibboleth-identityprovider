
package edu.internet2.middleware.shibboleth.hs.provider;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.apache.log4j.Logger;
import org.opensaml.QName;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.AuthNPrincipal;
import edu.internet2.middleware.shibboleth.common.BaseNameIdentifierMapping;
import edu.internet2.middleware.shibboleth.common.IdentityProvider;
import edu.internet2.middleware.shibboleth.common.InvalidNameIdentifierException;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMapping;
import edu.internet2.middleware.shibboleth.common.NameIdentifierMappingException;
import edu.internet2.middleware.shibboleth.common.ServiceProvider;

/**
 * <code>HSNameIdentifierMapping</code> implementation that translates principal names to E-Auth compliant
 * X509SubjectNames.
 * 
 * @author Walter Hoehn
 */
public class X509SubjectNameNameIdentifierMapping extends BaseNameIdentifierMapping implements NameIdentifierMapping {

	private static Logger log = Logger.getLogger(X509SubjectNameNameIdentifierMapping.class.getName());
	private String regexTemplate = ".*uid=([^,/]+).*";
	private Pattern regex;
	private String qualifier;
	private String internalNameContext;
	private QName[] errorCodes = new QName[0];

	public X509SubjectNameNameIdentifierMapping(Element config) throws NameIdentifierMappingException {

		super(config);

		String rawRegex = ((Element) config).getAttribute("regex");
		if (rawRegex != null && !rawRegex.equals("")) {
			try {
				regex = Pattern.compile(rawRegex);
			} catch (PatternSyntaxException e) {
				log.error("Supplied (regex) attribute is not a valid regular expressions.  Using default value.");
				regex = Pattern.compile(regexTemplate);
			}
		} else {
			regex = Pattern.compile(regexTemplate);
		}

		qualifier = ((Element) config).getAttribute("qualifier");
		if (qualifier == null || qualifier.equals("")) {
			log.error("The X509SubjectName NameMapping requires a (qualifier) attribute.");
			throw new NameIdentifierMappingException(
					"Invalid configuration.  Unable to initialize X509SubjectName Mapping.");
		}

		internalNameContext = ((Element) config).getAttribute("internalNameContext");
		if (internalNameContext == null || internalNameContext.equals("")) {
			log.error("The X509SubjectName NameMapping requires a (internalNameContext) attribute.");
			throw new NameIdentifierMappingException(
					"Invalid configuration.  Unable to initialize X509SubjectName Mapping.");
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see edu.internet2.middleware.shibboleth.common.NameIdentifierMapping#getPrincipal(org.opensaml.SAMLNameIdentifier,
	 *      edu.internet2.middleware.shibboleth.common.ServiceProvider,
	 *      edu.internet2.middleware.shibboleth.common.IdentityProvider)
	 */

	public AuthNPrincipal getPrincipal(SAMLNameIdentifier nameId, ServiceProvider sProv, IdentityProvider idProv)
			throws NameIdentifierMappingException, InvalidNameIdentifierException {

		if (!nameId.getNameQualifier().equals(qualifier)) {
			log.error("The name qualifier (" + nameId.getNameQualifier()
					+ ") for the referenced subject is not valid for this identity provider.");
			throw new NameIdentifierMappingException("The name qualifier (" + nameId.getNameQualifier()
					+ ") for the referenced subject is not valid for this identity provider.");
		}

		Matcher matcher = regex.matcher(nameId.getName());
		matcher.find();
		String principal = matcher.group(1);
		if (principal == null) { throw new InvalidNameIdentifierException("Unable to map X509SubjectName ("
				+ nameId.getName() + ") to a local principal.", errorCodes); }
		return new AuthNPrincipal(principal);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see edu.internet2.middleware.shibboleth.hs.HSNameIdentifierMapping#getNameIdentifierName(edu.internet2.middleware.shibboleth.common.AuthNPrincipal,
	 *      edu.internet2.middleware.shibboleth.common.ServiceProvider,
	 *      edu.internet2.middleware.shibboleth.common.IdentityProvider)
	 */
	public SAMLNameIdentifier getNameIdentifierName(AuthNPrincipal principal, ServiceProvider sProv,
			IdentityProvider idProv) throws NameIdentifierMappingException {

		try {
			return new SAMLNameIdentifier(internalNameContext.replaceAll("%PRINCIPAL%", principal.getName()),
					qualifier, getNameIdentifierFormat().toString());
		} catch (SAMLException e) {
			throw new NameIdentifierMappingException("Unable to generate X509 SubjectName: " + e);
		}

	}

}