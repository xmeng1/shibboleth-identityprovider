package edu.internet2.middleware.eduPerson;

import java.util.Iterator;
import java.util.Vector;
import org.opensaml.*;
import org.w3c.dom.*;

/**
 *  Basic implementation of a scoped, eduPerson SAML attribute
 *
 * @author     Scott Cantor
 * @created    May 9, 2002
 */
public class ScopedAttribute extends SAMLAttribute
{
    /**  Default attribute scope */
    protected String defaultScope = null;

    /**  Scopes of the attribute values */
    protected Vector scopes = new Vector();

    /**
     *  Constructor for the ScopedAttribute object
     *
     * @param  name               Name of attribute
     * @param  namespace          Namespace/qualifier of attribute
     * @param  type               The schema type of attribute value(s)
     * @param  lifetime           Effective lifetime of attribute's value(s) in
     *      seconds (0 means infinite)
     * @param  values             An array of attribute values
     * @param  defaultScope       The default scope to apply for values
     * @param  scopes             Scopes of the attribute values
     * @exception  SAMLException  Thrown if attribute cannot be built from the
     *      supplied information
     */
    public ScopedAttribute(String name, String namespace, QName type, long lifetime, Object[] values,
                           String defaultScope, String[] scopes)
        throws SAMLException
    {
        super(name, namespace, type, lifetime, values);
        this.defaultScope = defaultScope;

        for (int i = 0; scopes != null && i < scopes.length; i++)
            this.scopes.add(scopes[i]);
    }

    /**
     *  Reconstructs and validates an attribute from a DOM tree<P>
     *
     *  Overrides the basic implementation to handle the same simple types, but
     *  also picks up scope.
     *
     * @param  e                  A DOM Attribute element
     * @exception  SAMLException  Thrown if the attribute cannot be constructed
     */
    public ScopedAttribute(Element e)
        throws SAMLException
    {
        super(e);

        // Default scope comes from subject.
        NodeList nlist = ((Element)e.getParentNode()).getElementsByTagNameNS(org.opensaml.XML.SAML_NS, "NameIdentifier");
        if (nlist.getLength() != 1)
            throw new InvalidAssertionException(SAMLException.RESPONDER, "ScopedAttribute() can't find saml:NameIdentifier in enclosing statement");
        defaultScope = ((Element)nlist.item(0)).getAttributeNS(null, "NameQualifier");
    }

    /**
     *  Gets the values of the SAML Attribute, serialized as strings with the
     *  effective scope appended
     *
     * @return    The array of values
     */
    public Object[] getValues()
    {
        if (values == null)
            return null;

        Object[] bufs = new Object[values.size()];
        for (int i = 0; i < values.size(); i++)
        {
            if (values.get(i) != null)
            {
                if (scopes != null && i < scopes.size() && scopes.get(i) != null)
                    bufs[i] = values.get(i).toString() + "@" + scopes.get(i);
                else
                    bufs[i] = values.get(i).toString() + "@" + defaultScope;
            }
        }
        return bufs;
    }

    /**
     *  Attribute acceptance hook used while consuming attributes from an
     *  assertion. Base class simply accepts anything. Override for desired
     *  behavior.
     *
     * @param  e  An AttributeValue element to check
     * @return    true iff the value is deemed acceptable
     */
    public boolean accept(Element e)
    {
        return true;
    }

    /**
     *  Adds a value to the state of the SAML Attribute<P>
     *
     *  This class supports a simple text node content model with a Scope
     *  attribute
     *
     * @param  e  The AttributeValue element containing the value to add
     * @return    true iff the value was understood
     */
    public boolean addValue(Element e)
    {
        if (super.addValue(e))
        {
            scopes.add(e.getAttributeNS(null,"Scope"));
            return true;
        }
        return false;
    }

    /**
     *  Overridden method to return a DOM tree representing the attribute<P>
     *
     *  Because attributes are generalized, this base method only handles simple
     *  attributes whose values are of uniform simple type and expressed in the
     *  DOM as a single text node within the AttributeValue element(s). The
     *  values are serialized using the toString() method.<P>
     *
     *  SAML applications should override this class and reimplement or
     *  supplement this method to handle other requirements.
     *
     * @param  doc  A Document object to use in manufacturing the tree
     * @return      Root "Attribute" element of a DOM tree
     */
    public Node toDOM(Document doc)
    {
        super.toDOM(doc);

        NodeList nlist = ((Element)root).getElementsByTagNameNS(org.opensaml.XML.SAML_NS, "AttributeValue");
        for (int i = 0; i < nlist.getLength(); i++)
        {
            ((Element)nlist.item(i)).removeAttributeNS(null, "Scope");
            String scope=scopes.get(i).toString();
            if (scope != null && !scope.equals(defaultScope))
                ((Element)nlist.item(i)).setAttributeNS(null, "Scope", scope);
        }

        return root;
    }
}

