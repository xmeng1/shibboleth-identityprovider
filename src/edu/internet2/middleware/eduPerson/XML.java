package edu.internet2.middleware.eduPerson;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 *  Utility class for XML constants and schema handling
 *
 * @author     Scott Cantor
 * @created    May 18, 2002
 */
public class XML
{
    /**  eduPerson XML namespace */
    public final static String EDUPERSON_NS = "urn:mace:eduPerson:1.0";

    /**  eduPerson XML schema identifier */
    public final static String EDUPERSON_SCHEMA_ID = "eduPerson.xsd";

    private static byte[] eduPerson_schema;

    /**
     *  Custom schema resolver class
     *
     * @author     Scott Cantor
     * @created    May 18, 2002
     */
    protected static class SchemaResolver implements EntityResolver
    {
        /**
         *  A customized entity resolver for the Shibboleth extension schema
         *
         * @param  publicId                 The public identifier of the entity
         * @param  systemId                 The system identifier of the entity
         * @return                          A source of bytes for the entity or
         *      null
         * @exception  SAXException         Raised if an XML parsing problem
         *      occurs
         * @exception  java.io.IOException  Raised if an I/O problem is detected
         */
        public InputSource resolveEntity(String publicId, String systemId)
            throws SAXException, java.io.IOException
        {
            InputSource src = null;
            if (systemId.endsWith('/' + EDUPERSON_SCHEMA_ID) && eduPerson_schema != null)
                src = new InputSource(new ByteArrayInputStream(eduPerson_schema));
            return src;
        }
    }

    static
    {
        try
        {
            StringBuffer buf = new StringBuffer(1024);
            InputStream xmlin = XML.class.getResourceAsStream("/schemas/" + EDUPERSON_SCHEMA_ID);
            if (xmlin == null)
                throw new RuntimeException("XML static initializer unable to locate eduPerson schema");
            else
            {
                int b;
                while ((b = xmlin.read()) != -1)
                    buf.append((char)b);
                eduPerson_schema = buf.toString().getBytes();
                xmlin.close();
            }
        }
        catch (java.io.IOException e)
        {
            throw new RuntimeException("XML static initializer caught an I/O error");
        }
    }
}

