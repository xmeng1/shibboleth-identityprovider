/*
 * XMLAAPImpl.java
 * 
 * Implement the AAP and AttributeRule interfaces using the XML Beans
 * generated from the <AttributeAcceptancePolicy> root element.
 * 
 * If an external AAP file is changed and reparsed, then a new instance
 * of this object must be created from the new XMLBean to replace the
 * previous object in the Config Map of AAP interface implementing 
 * objects key by its URI.
 * 
 * --------------------
 * Copyright 2002, 2004 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
 * [Thats all we have to say to protect ourselves]
 * Your permission to use this code is governed by "The Shibboleth License".
 * A copy may be found at http://shibboleth.internet2.edu/license.html
 * [Nothing in copyright law requires license text in every file.]
 */
package edu.internet2.middleware.shibboleth.serviceprovider;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.apache.xmlbeans.XmlException;
import org.opensaml.SAMLAttribute;

import x0.maceShibboleth1.AttributeAcceptancePolicyDocument;
import x0.maceShibboleth1.AttributeRuleType;
import x0.maceShibboleth1.AttributeRuleValueType;
import x0.maceShibboleth1.AttributeAcceptancePolicyDocument.AttributeAcceptancePolicy;
import x0.maceShibboleth1.SiteRuleDocument.SiteRule;
import x0.maceShibboleth1.SiteRuleType.Scope;
import x0.maceShibboleth1.SiteRuleType;
import edu.internet2.middleware.shibboleth.common.AAP;
import edu.internet2.middleware.shibboleth.common.AttributeRule;
import edu.internet2.middleware.shibboleth.metadata.EntityDescriptor;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * An XMLAAPImpl object implements the AAP interface by creating
 * and maintaining objects that implement the AttributeRule interface.
 * The real work is done in AttributeRule.apply() where a 
 * SAML Attribute Assertion is compared to policy and invalid values
 * or assertions are removed.
 * 
 * A new instance of this object should be created whenever the
 * AAP XML configuration file is changed and reparsed. The new object
 * should then replace the old object in the Map that ServiceProviderConfig
 * maintains keyed by file URI, holding implementors of the AAP interface.
 */
public class XMLAAPImpl 
	implements AAP,
	PluggableConfigurationComponent {
	
	private static Logger log = Logger.getLogger(XMLAAPImpl.class);
	
	private boolean anyAttribute=false;
	private AttributeRule[] attributeRules;


	public void initialize(Node dom) 
		throws XmlException {
	    AttributeAcceptancePolicyDocument bean = AttributeAcceptancePolicyDocument.Factory.parse(dom);
	    AttributeAcceptancePolicy aapbean = bean.getAttributeAcceptancePolicy();
		if  (null!=aapbean.getAnyAttribute())
			anyAttribute=true; // There is an anyAttribute element
		
		AttributeRuleType[] rulebeans = aapbean.getAttributeRuleArray();
		attributeRules = new AttributeRule[rulebeans.length];
		for (int i=0;i<rulebeans.length;i++) {
			attributeRules[i]=new XMLAttributeRuleImpl(rulebeans[i]);
		}
	}
	
	
	public boolean isAnyAttribute() {
		return anyAttribute;
	}

	// The lookup could use a Map, but the array is not expected to
	// be long, and there are three keys to process. We can add a
	// Map later if needed.
	
	public AttributeRule lookup(String attrName, String attrNamespace) {
		for (int i=0;i<attributeRules.length;i++) {
			AttributeRule attributeRule = attributeRules[i];
			String name = attributeRule.getName();
			String namespace = attributeRule.getNamespace();
			if (name!=null && 
			        name.equals(attrName)) {
			        if (attrNamespace==null ||
			           (namespace!=null &&
					    namespace.equals(attrNamespace)))
			             return attributeRule;
			}
		}
		return null;
	}

	public AttributeRule lookup(String alias) {
		for (int i=0;i<attributeRules.length;i++) {
			AttributeRule attributeRule = attributeRules[i];
			if (attributeRule.getAlias().equals(alias))
				return attributeRule;
		}
		return null;
	}

	public AttributeRule[] getAttributeRules() {
		return attributeRules;
	}
	
	
	/**
	 * Implement the ...commmon.AttributeRules interface by wrapping the XMLBean
	 * 
	 * @author Howard Gilbert
	 */
	public class XMLAttributeRuleImpl implements AttributeRule {
		
		AttributeRuleType bean;
		Map /*<Entityname-String,SiteRule>*/ siteMap = new HashMap();
		
		XMLAttributeRuleImpl(AttributeRuleType bean) {
			this.bean=bean;
			SiteRule[] siteRules = bean.getSiteRuleArray();
			for (int i=0;i<siteRules.length;i++) {
				SiteRule siteRule = siteRules[i];
				String entityName = siteRule.getName();
				siteMap.put(entityName,siteRule);
			}
		}

		public String getName() {
			return bean.getName();
		}

		public String getNamespace() {
			return bean.getNamespace();
		}

		public String getAlias() {
			return bean.getAlias();
		}

		public String getHeader() {
			return bean.getHeader();
		}

		/**
		 * Apply this AttributeRule to values of a SAMLAttribute
		 */
		public void apply(EntityDescriptor originSite, SAMLAttribute attribute) {
			Iterator values = attribute.getValues();
			int i=0;
			while(values.hasNext()) {
				Element valueElement = (Element) values.next();
				if (!acceptableValue(originSite,valueElement)|| 
					!scopeCheck(originSite,valueElement)) {
					attribute.removeValue(i);
				} else {
					i++;
				}
			}
		}
		
		
		
		/**
		 * Apply an array of Scope elements to a SAML scope attribute.
		 * 
		 * <p>Scope rules can accept or reject their matches.
		 * Any match to a rejection is immediately fatal. Otherwise,
		 * there must have been one accept by the end of the scan.</p>
		 * 
		 * <p>The return is a three state Boolean object. A Boolean(false)
		 * is a rejection. A Boolean(true) is a tentative approval. A 
		 * null is neutral (no rejection, but no match).
		 */
		private Boolean applyScopeRules(Scope[] scopeArray, String scopeAttribute) {
			Boolean decision = null;
			
			for (int i=0;i<scopeArray.length;i++) {
				Scope scoperule = scopeArray[i];
				
				boolean accept = scoperule.getAccept();
				int type = scoperule.getType().intValue();
				String value = scoperule.getStringValue();
				
				switch (type) {
				case AttributeRuleValueType.INT_REGEXP:
					if (Pattern.matches(scopeAttribute,value)) {
						if (accept && decision==null)
							decision=Boolean.TRUE; // Tentative approval
						else
							return Boolean.FALSE;  // Deny immediate
					}
				break;
				case AttributeRuleValueType.INT_XPATH:
					log.warn("implementation does not support XPath value rules");
				break;
				default:
					if (scopeAttribute.equals(value)) {
						if (accept && decision==null)
							decision=Boolean.TRUE; // Tentative approval
						else
							return Boolean.FALSE;  // Deny immediate
					}
				break;
				}
			}
			return decision;
			
		}
		
		/**
		 * Apply AnySite scope rules, then rules for Origin site.
		 * 
		 * @param originSite Metadata for origin site
		 * @param ele        SAML attribute value
		 * @return           true if OK, false if failed test
		 */
		private boolean scopeCheck(EntityDescriptor originSite, Element ele) {
			
			String scopeAttribute = ele.getAttributeNS(null,"Scope");
			if (scopeAttribute==null || 
				scopeAttribute.length()==0)
				return true;  // Nothing to verify, so its OK
			
			Boolean anypermit = null; // null is neutral on decision
			Boolean sitepermit = null;
			
			// AnySite scope test
			Scope[] scopeArray = bean.getAnySite().getScopeArray();
			anypermit = applyScopeRules(scopeArray,scopeAttribute);
			if (anypermit!=null && // if null (neutral) fall through
				!anypermit.booleanValue()) // if tentative true, fall through
				return false; // Boolean(false) is immediate deny
			
			// Now find origin site rule, if present
			String os = originSite.getId();
			SiteRule siteRule = (SiteRule) siteMap.get(os);
			
			if (siteRule!=null) {
				scopeArray = siteRule.getScopeArray();
				sitepermit = applyScopeRules(scopeArray,scopeAttribute);
				if (sitepermit!=null &&
					!sitepermit.booleanValue()) 
					return false;
			}

			// Now, since any Boolean(false) would have generated a 
			// rejection, any non-null value is a Boolean(true). 
			// Accept if either found an accept
			return anypermit!=null || sitepermit!=null;
		}

		/**
		 * Determine if SAML value matches any Value rule in list
		 * 
		 * @param values Value rules from AAP
		 * @param node   SAML value
		 * @return
		 */
		private boolean checkForMatchingValue(SiteRuleType.Value[] values, Node node) {
			String nodeValue = node.getNodeValue();
			for (int i=0;i<values.length;i++) {
				SiteRuleType.Value value = values[i];
				String valueContents = value.getStringValue();
				switch (value.getType().intValue()) {
				 	case AttributeRuleValueType.INT_REGEXP:
				 		if (Pattern.matches(valueContents,nodeValue))
							return true;
				 		break;
				 	case AttributeRuleValueType.INT_XPATH:
				 		//log.warn("implementation does not support XPath value rules");
				 		break;
				 	default:
				 		if (nodeValue.equals(valueContents))
							return true;
				 		break;
				}
			}
			return false;
			
		}

		
		/**
		 * Apply AnySite Value rules, then rules for Origin site
		 * @param originSite Metadata for Origin site
		 * @param ele SAML Attribute value
		 * @return true to continue with scope check, false to reject now
		 */
		private boolean acceptableValue(EntityDescriptor originSite, Element ele) {
			
			// any site, any value
			if (bean.getAnySite().getAnyValue()!=null) 
				return true;
			
			Node node = ele.getFirstChild();
			boolean simple = node.getNodeType()==Node.TEXT_NODE;
			
			// any site, specific value
			if (simple) {
				SiteRuleType.Value[] values = bean.getAnySite().getValueArray();
				if (checkForMatchingValue(values,node))
					return true;
			}
			
			// Specific site
			String os = originSite.getId();
			SiteRule siteRule = (SiteRule) siteMap.get(os);
			if (siteRule==null) {
				log.warn("Site "+os+" not found in ruleset "+this.getName());
				return false;
			}
			if (siteRule.getAnyValue()!=null) {
				return true;
			}
			SiteRuleType.Value[] values = siteRule.getValueArray();
			if (checkForMatchingValue(values,node))
				return true;
			
			return false;
		}
	}


    /**
     * @return
     */
    public String getSchemaPathname() {
       return null;
    }
}
