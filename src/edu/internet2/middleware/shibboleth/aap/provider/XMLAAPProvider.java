package edu.internet2.middleware.shibboleth.aap.provider;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.PatternSyntaxException;

import org.apache.log4j.Logger;
import org.opensaml.MalformedException;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLException;
import org.opensaml.XML;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import edu.internet2.middleware.shibboleth.aap.AAP;
import edu.internet2.middleware.shibboleth.aap.AttributeRule;
import edu.internet2.middleware.shibboleth.common.Constants;
import edu.internet2.middleware.shibboleth.metadata.EntitiesDescriptor;
import edu.internet2.middleware.shibboleth.metadata.RoleDescriptor;
import edu.internet2.middleware.shibboleth.metadata.ScopedRoleDescriptor;
import edu.internet2.middleware.shibboleth.metadata.ScopedRoleDescriptor.Scope;

public class XMLAAPProvider implements AAP {

    private static Logger log = Logger.getLogger(XMLAAPProvider.class.getName());
    private Map /* <String,AttributeRule> */ attrmap = new HashMap();
    private Map /* <String,AttributeRule> */ aliasmap = new HashMap();
    private boolean anyAttribute = false;
    
    public XMLAAPProvider(Element e) throws MalformedException {
        if (!XML.isElementNamed(e,edu.internet2.middleware.shibboleth.common.XML.SHIB_NS,"AttributeAcceptancePolicy")) {
            log.error("Construction requires a valid AAP file: (shib:AttributeAcceptancePolicy as root element)");
            throw new MalformedException("Construction requires a valid AAP file: (shib:AttributeAcceptancePolicy as root element)");
        }

        // Check for AnyAttribute element.
        Element anyAttr = XML.getFirstChildElement(e,edu.internet2.middleware.shibboleth.common.XML.SHIB_NS,"AnyAttribute");
        if (anyAttr != null) {
            anyAttribute = true;
            log.warn("<AnyAttribute> found, will short-circuit all attribute value and scope filtering");
        }

        // Loop over the AttributeRule elements.
        NodeList nlist = e.getElementsByTagNameNS(edu.internet2.middleware.shibboleth.common.XML.SHIB_NS,"AttributeRule");
        for (int i=0; i<nlist.getLength(); i++) {
            AttributeRule rule=new XMLAttributeRule((Element)(nlist.item(i)));
            String key = rule.getName() + "!!" + ((rule.getNamespace() != null) ? rule.getNamespace() : Constants.SHIB_ATTRIBUTE_NAMESPACE_URI); 
            attrmap.put(key,rule);
            if (rule.getAlias() != null)
                aliasmap.put(rule.getAlias(),rule);
        }
    }
    
    class XMLAttributeRule implements AttributeRule {

        private String name = null;
        private String namespace = null;
        private String factory = null;
        private String alias = null;
        private String header = null;
        private boolean caseSensitive = true;
        private boolean scoped = false;
        private SiteRule anySiteRule = new SiteRule();
        private Map /* <String,SiteRule> */ siteMap = new HashMap(); 
        
        class Rule {
            static final int LITERAL = 0;
            static final int REGEXP = 1;
            static final int XPATH = 2;
            
            Rule(int type, String expression) {
                this.type = type;
                this.expression = expression;
            }
            int type;
            String expression;
        }
        
        class SiteRule {
            boolean anyValue = false;
            ArrayList valueDenials = new ArrayList();
            ArrayList valueAccepts = new ArrayList();
            ArrayList scopeDenials = new ArrayList();
            ArrayList scopeAccepts = new ArrayList();
        }
        
        XMLAttributeRule(Element e) throws MalformedException {
            factory = XML.assign(e.getAttributeNS(null,"Factory"));
            alias = XML.assign(e.getAttributeNS(null,"Alias"));
            header = XML.assign(e.getAttributeNS(null,"Header"));
            name = XML.assign(e.getAttributeNS(null,"Name"));
            namespace = XML.assign(e.getAttributeNS(null,"Namespace"));
            if (namespace == null)
                namespace = Constants.SHIB_ATTRIBUTE_NAMESPACE_URI;
            
            String flag=XML.assign(e.getAttributeNS(null,"Scoped"));
            scoped=(XML.safeCompare(flag,"1") || XML.safeCompare(flag,"true"));
            flag=XML.assign(e.getAttributeNS(null,"CaseSensitive"));
            caseSensitive=(XML.isEmpty(flag) || XML.safeCompare(flag,"1") || XML.safeCompare(flag,"true"));

            // Check for an AnySite rule.
            Element anysite = XML.getFirstChildElement(e);
            if (anysite != null && XML.isElementNamed(anysite,edu.internet2.middleware.shibboleth.common.XML.SHIB_NS,"AnySite")) {
                // Process Scope elements.
                NodeList vlist = anysite.getElementsByTagNameNS(edu.internet2.middleware.shibboleth.common.XML.SHIB_NS,"Scope");
                for (int i=0; i < vlist.getLength(); i++) {
                    scoped=true;
                    Element se=(Element)vlist.item(i);
                    Node valnode=se.getFirstChild();
                    if (valnode != null && valnode.getNodeType()==Node.TEXT_NODE) {
                        String accept=se.getAttributeNS(null,"Accept");
                        if (XML.isEmpty(accept) || XML.safeCompare(flag,"1") || XML.safeCompare(flag,"true"))
                            anySiteRule.scopeAccepts.add(new Rule(toValueType(se),valnode.getNodeValue()));
                        else
                            anySiteRule.scopeDenials.add(new Rule(toValueType(se),valnode.getNodeValue()));
                    }
                }

                // Check for an AnyValue rule.
                vlist = anysite.getElementsByTagNameNS(edu.internet2.middleware.shibboleth.common.XML.SHIB_NS,"AnyValue");
                if (vlist.getLength() > 0) {
                    anySiteRule.anyValue=true;
                }
                else {
                    // Process each Value element.
                    vlist = anysite.getElementsByTagNameNS(edu.internet2.middleware.shibboleth.common.XML.SHIB_NS,"Value");
                    for (int j=0; j<vlist.getLength(); j++) {
                        Element ve=(Element)vlist.item(j);
                        Node valnode=ve.getFirstChild();
                        if (valnode != null && valnode.getNodeType()==Node.TEXT_NODE) {
                            String accept=ve.getAttributeNS(null,"Accept");
                            if (XML.isEmpty(accept) || XML.safeCompare(flag,"1") || XML.safeCompare(flag,"true"))
                                anySiteRule.valueAccepts.add(new Rule(toValueType(ve),valnode.getNodeValue()));
                            else
                                anySiteRule.valueDenials.add(new Rule(toValueType(ve),valnode.getNodeValue()));
                        }
                    }
                }
            }

            // Loop over the SiteRule elements.
            NodeList slist = e.getElementsByTagNameNS(edu.internet2.middleware.shibboleth.common.XML.SHIB_NS,"SiteRule");
            for (int k=0; k<slist.getLength(); k++) {
                String srulename=((Element)slist.item(k)).getAttributeNS(null,"Name");
                SiteRule srule = new SiteRule();
                siteMap.put(srulename,srule);

                // Process Scope elements.
                NodeList vlist = ((Element)slist.item(k)).getElementsByTagNameNS(edu.internet2.middleware.shibboleth.common.XML.SHIB_NS,"Scope");
                for (int i=0; i<vlist.getLength(); i++) {
                    scoped=true;
                    Element se=(Element)vlist.item(i);
                    Node valnode=se.getFirstChild();
                    if (valnode != null && valnode.getNodeType()==Node.TEXT_NODE)
                    {
                        String accept=se.getAttributeNS(null,"Accept");
                        if (XML.isEmpty(accept) || XML.safeCompare(flag,"1") || XML.safeCompare(flag,"true"))
                            srule.scopeAccepts.add(new Rule(toValueType(se),valnode.getNodeValue()));
                        else
                            srule.scopeDenials.add(new Rule(toValueType(se),valnode.getNodeValue()));
                    }
                }

                // Check for an AnyValue rule.
                vlist = ((Element)slist.item(k)).getElementsByTagNameNS(edu.internet2.middleware.shibboleth.common.XML.SHIB_NS,"AnyValue");
                if (vlist.getLength() > 0) {
                    srule.anyValue=true;
                }
                else {
                    // Process each Value element.
                    vlist = ((Element)slist.item(k)).getElementsByTagNameNS(edu.internet2.middleware.shibboleth.common.XML.SHIB_NS,"Value");
                    for (int j=0; j<vlist.getLength(); j++) {
                        Element ve=(Element)vlist.item(j);
                        Node valnode=ve.getFirstChild();
                        if (valnode != null && valnode.getNodeType()==Node.TEXT_NODE) {
                            String accept=ve.getAttributeNS(null,"Accept");
                            if (XML.isEmpty(accept) || XML.safeCompare(flag,"1") || XML.safeCompare(flag,"true"))
                                srule.valueAccepts.add(new Rule(toValueType(ve),valnode.getNodeValue()));
                            else
                                srule.valueDenials.add(new Rule(toValueType(ve),valnode.getNodeValue()));
                        }
                    }
                }
            }
        }
        
        private int toValueType(Element e) throws MalformedException {
            if (!e.hasAttributeNS(null,"Type") || XML.safeCompare("literal",e.getAttributeNS(null,"Type")))
                return Rule.LITERAL;
            else if (XML.safeCompare("regexp",e.getAttributeNS(null,"Type")))
                return Rule.REGEXP;
            else if (XML.safeCompare("xpath",e.getAttributeNS(null,"Type")))
                return Rule.XPATH;
            throw new MalformedException("Found an invalid value or scope rule type.");
        }
        
        public String getName() {
            return name;
        }

        public String getNamespace() {
            return namespace;
        }

        public String getFactory() {
            return factory;
        }

        public String getAlias() {
            return alias;
        }

        public String getHeader() {
            return header;
        }

        public boolean getCaseSensitive() {
            return caseSensitive;
        }

        public boolean getScoped() {
            return scoped;
        }

        public void apply(SAMLAttribute attribute, RoleDescriptor role) throws SAMLException {
            ScopedRoleDescriptor scoper = ((role instanceof ScopedRoleDescriptor) ? (ScopedRoleDescriptor)role : null);
            
            // This is a little tricky because if we remove anything,
            // the NodeList is out of sync with the underlying object.
            // We have to maintain a separate index counter into the object.
            int index = 0;
            NodeList vals = attribute.getValueElements();
            for (int i=0; i < vals.getLength(); i++) {
                if (!accept((Element)vals.item(i),scoper))
                    attribute.removeValue(index);
                else
                    index++;
            }
        }

        boolean match(String exp, String test) {
            try {
                if (test.matches(exp))
                    return true;
            }
            catch (PatternSyntaxException ex) {
                log.error("caught exception while parsing regular expression ()");
            }
            return false;
        }

        public boolean scopeCheck(Element e, ScopedRoleDescriptor role, Collection ruleStack) {
            // Are we scoped?
            String scope=XML.assign(e.getAttributeNS(null,"Scope"));
            if (scope == null) {
                // Are we allowed to be unscoped?
                if (scoped)
                    log.warn("attribute (" + name + ") is scoped, no scope supplied, rejecting it");
                return !scoped;
            }

            // With the new algorithm, we evaluate each matching rule in sequence, separately.
            Iterator srules = ruleStack.iterator();
            while (srules.hasNext()) {
                SiteRule srule = (SiteRule)srules.next();
                
                // Now run any denials.
                Iterator denials = srule.scopeDenials.iterator();
                while (denials.hasNext()) {
                    Rule denial = (Rule)denials.next();
                    if ((denial.type==Rule.LITERAL && XML.safeCompare(denial.expression,scope)) ||
                        (denial.type==Rule.REGEXP && match(denial.expression,scope))) {
                        log.warn("attribute (" + name + ") scope {" + scope + "} denied by site rule, rejecting it");
                        return false;
                    }
                    else if (denial.type==Rule.XPATH)
                        log.warn("scope checking does not permit XPath rules");
                }

                // Now run any accepts.
                Iterator accepts = srule.scopeAccepts.iterator();
                while (accepts.hasNext()) {
                    Rule accept = (Rule)accepts.next();
                    if ((accept.type==Rule.LITERAL && XML.safeCompare(accept.expression,scope)) ||
                        (accept.type==Rule.REGEXP && match(accept.expression,scope))) {
                        log.debug("matching site rule, scope match");
                        return true;
                    }
                    else if (accept.type==Rule.XPATH)
                        log.warn("scope checking does not permit XPath rules");
                }
            }

            // If we still can't decide, defer to metadata.
            if (role != null) {
                Iterator scopes=role.getScopes();
                while (scopes.hasNext()) {
                    ScopedRoleDescriptor.Scope p = (Scope)scopes.next();
                    if ((p.regexp && match(p.scope,scope)) || XML.safeCompare(p.scope,scope)) {
                        log.debug("scope match via site metadata");
                        return true;
                    }
                }
            }
            
            log.warn("attribute (" + name + ") scope {" + scope + "} not accepted");
            return false;
        }
        
        boolean accept(Element e, ScopedRoleDescriptor role) {
            log.debug("evaluating value for attribute (" + name + ") from site (" +
                    ((role!=null) ? role.getEntityDescriptor().getId() : "<unspecified>") +
                    ")");
            
            // This is a complete revamp. The "any" cases become a degenerate case, the "least-specific" matching rule.
            // The first step is to build a list of matching rules, most-specific to least-specific.
            
            ArrayList ruleStack = new ArrayList();
            if (role != null) {
                // Primary match is against entityID.
                SiteRule srule=(SiteRule)siteMap.get(role.getEntityDescriptor().getId());
                if (srule!=null)
                    ruleStack.add(srule);
                
                // Secondary matches are on groups.
                EntitiesDescriptor group=role.getEntityDescriptor().getEntitiesDescriptor();
                while (group != null) {
                    srule=(SiteRule)siteMap.get(group.getName());
                    if (srule!=null)
                        ruleStack.add(srule);
                    group = group.getEntitiesDescriptor();
                }
            }
            // Tertiary match is the AnySite rule.
            ruleStack.add(anySiteRule);

            // Still don't support complex content models...
            Node n=e.getFirstChild();
            boolean bSimple=(n != null && n.getNodeType()==Node.TEXT_NODE);

            // With the new algorithm, we evaluate each matching rule in sequence, separately.
            Iterator srules = ruleStack.iterator();
            while (srules.hasNext()) {
                SiteRule srule = (SiteRule)srules.next();
                
                // Check for shortcut AnyValue blanket rule.
                if (srule.anyValue) {
                    log.debug("matching site rule, any value match");
                    return scopeCheck(e,role,ruleStack);
                }

                // Now run any denials.
                Iterator denials = srule.valueDenials.iterator();
                while (bSimple && denials.hasNext()) {
                    Rule denial = (Rule)denials.next();
                    switch (denial.type) {
                        case Rule.LITERAL:
                            if ((caseSensitive && !XML.safeCompare(denial.expression,n.getNodeValue())) ||
                                (!caseSensitive && denial.expression.equalsIgnoreCase(n.getNodeValue()))) {
                                log.warn("attribute (" + name + ") value explicitly denied by site rule, rejecting it");
                                return false;
                            }
                            break;
                        
                        case Rule.REGEXP:
                            if (match(denial.expression,n.getNodeValue())) {
                                log.warn("attribute (" + name + ") value explicitly denied by site rule, rejecting it");
                                return false;
                            }
                            break;
                        
                        case Rule.XPATH:
                            log.warn("implementation does not support XPath value rules");
                            break;
                    }
                }

                // Now run any accepts.
                Iterator accepts = srule.valueAccepts.iterator();
                while (bSimple && accepts.hasNext()) {
                    Rule accept = (Rule)accepts.next();
                    switch (accept.type) {
                        case Rule.LITERAL:
                            if ((caseSensitive && !XML.safeCompare(accept.expression,n.getNodeValue())) ||
                                (!caseSensitive && accept.expression.equalsIgnoreCase(n.getNodeValue()))) {
                                log.debug("site rule, value match");
                                return scopeCheck(e,role,ruleStack);
                            }
                            break;
                        
                        case Rule.REGEXP:
                            if (match(accept.expression,n.getNodeValue())) {
                                log.debug("site rule, value match");
                                return scopeCheck(e,role,ruleStack);
                            }
                            break;
                        
                        case Rule.XPATH:
                            log.warn("implementation does not support XPath value rules");
                            break;
                    }
                }
            }

            log.warn((bSimple ? "" : "complex ") + "attribute (" + name + ") value {" +
                    n.getNodeValue() + ") could not be validated by policy, rejecting it"
                    );
            return false;
        }
    }
    
    public boolean anyAttribute() {
        return anyAttribute;
    }

    public AttributeRule lookup(String name, String namespace) {
        return (AttributeRule)attrmap.get(name + "||" + namespace);
    }

    public AttributeRule lookup(String alias) {
        return (AttributeRule)aliasmap.get(alias);
    }

    public Iterator getAttributeRules() {
        return attrmap.values().iterator();
    }
}
