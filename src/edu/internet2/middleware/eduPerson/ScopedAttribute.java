/* 
 * The Shibboleth License, Version 1. 
 * Copyright (c) 2002 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
 * 
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this 
 * list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution, if any, must include 
 * the following acknowledgment: "This product includes software developed by 
 * the University Corporation for Advanced Internet Development 
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement 
 * may appear in the software itself, if and wherever such third-party 
 * acknowledgments normally appear.
 * 
 * Neither the name of Shibboleth nor the names of its contributors, nor 
 * Internet2, nor the University Corporation for Advanced Internet Development, 
 * Inc., nor UCAID may be used to endorse or promote products derived from this 
 * software without specific prior written permission. For written permission, 
 * please contact shibboleth@shibboleth.org
 * 
 * Products derived from this software may not be called Shibboleth, Internet2, 
 * UCAID, or the University Corporation for Advanced Internet Development, nor 
 * may Shibboleth appear in their name, without prior written permission of the 
 * University Corporation for Advanced Internet Development.
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK 
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY 
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.internet2.middleware.eduPerson;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import org.opensaml.*;
import org.w3c.dom.*;

/**
 *  Basic implementation of a scoped, eduPerson SAML attribute
 *
 * @author     Scott Cantor
 * @created    May 9, 2002
 */
public class ScopedAttribute extends SAMLAttribute implements Cloneable
{
    /**  Default attribute scope */
    protected String defaultScope = null;

    /**  Scopes of the attribute values */
    protected ArrayList scopes = new ArrayList();

    /**
     *  Constructor for the ScopedAttribute object
     *
     * @param  name               Name of attribute
     * @param  namespace          Namespace/qualifier of attribute
     * @param  defaultScope       The default scope to apply for values
     * @param  type               The schema type of attribute value(s)
     * @param  lifetime           Effective lifetime of attribute's value(s) in
     *      seconds (0 means infinite)
     * @param  scopes             Scopes of the attribute values
     * @param  values             A set of attribute values
     * @exception  SAMLException  Thrown if attribute cannot be built from the
     *      supplied information
     */
    public ScopedAttribute(String name, String namespace, String defaultScope, QName type, long lifetime,
                           Collection scopes, Collection values)
        throws SAMLException
    {
        super(name, namespace, type, lifetime, values);
        this.defaultScope = defaultScope;

        if (scopes != null)
            this.scopes.addAll(scopes);
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
        if (nlist ==null || nlist.getLength() != 1)
            throw new MalformedException(SAMLException.RESPONDER, "ScopedAttribute() can't find saml:NameIdentifier in enclosing statement");
        defaultScope = ((Element)nlist.item(0)).getAttributeNS(null, "NameQualifier");
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
     *  Gets the values of the SAML Attribute, serialized as strings with the
     *  effective scope appended
     *
     * @return    The attribute's values
     */
    public Iterator getValues()
    {
        if (values == null)
            return null;

        ArrayList bufs = new ArrayList(values.size());
        for (int i = 0; i < values.size(); i++)
        {
            if (values.get(i) != null)
            {
                if (i < scopes.size() && scopes.get(i) != null)
                    bufs.set(i, values.get(i).toString() + "@" + scopes.get(i));
                else
                    bufs.set(i, values.get(i).toString() + "@" + defaultScope);
            }
        }
        return bufs.iterator();
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
        
        int i=0;
        Node n=root.getFirstChild();
        while (n!=null)
        {
            if (n.getNodeType()==Node.ELEMENT_NODE)
            {
                ((Element)n).removeAttributeNS(null,"Scope");
                if (i < scopes.size() && scopes.get(i)!=null && !scopes.get(i).equals(defaultScope))
                    ((Element)n).setAttributeNS(null,"Scope",(String)scopes.get(i));
            }
            n=n.getNextSibling();
        }

        return root;
    }

    /**
     *  Copies a SAML object such that no dependencies exist between the original
     *  and the copy
     * 
     * @return      The new object
     * @see java.lang.Object#clone()
     */
    public Object clone()
        throws CloneNotSupportedException
    {
        ScopedAttribute dup=(ScopedAttribute)super.clone();

        dup.scopes = (ArrayList)scopes.clone();

        return dup;
    }
}

