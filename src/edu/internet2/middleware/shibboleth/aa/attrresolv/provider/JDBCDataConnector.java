/*
 * Copyright (c) 2003 National Research Council of Canada
 *
 * Permission is hereby granted, free of charge, to any person 
 * obtaining a copy of this software and associated documentation 
 * files (the "Software"), to deal in the Software without 
 * restriction, including without limitation the rights to use, 
 * copy, modify, merge, publish, distribute, sublicense, and/or 
 * sell copies of the Software, and to permit persons to whom the 
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR 
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */

package edu.internet2.middleware.shibboleth.aa.attrresolv.provider;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.Principal;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver;
import edu.internet2.middleware.shibboleth.aa.attrresolv.DataConnectorPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugInException;

/*
 * Built at the Canada Institute for Scientific and Technical Information (CISTI 
 * <ahref="http://www.cisti-icist.nrc-cnrc.gc.ca/">http://www.cisti-icist.nrc-cnrc.gc.ca/</a>, 
 * the National Research Council Canada 
 * (NRC <a href="http://www.nrc-cnrc.gc.ca/">http://www.nrc-cnrc.gc.ca/</a>)
 * by David Dearman, COOP student from Dalhousie University,
 * under the direction of Glen Newton, Head research (IT)
 * <ahref="mailto:glen.newton@nrc-cnrc.gc.ca">glen.newton@nrc-cnrc.gc.ca</a>. 
 */

/**
 * Data Connector that uses JDBC to access user attributes stored in databases.
 *
 * @author David Dearman (dearman@cs.dal.ca)
 */

public class JDBCDataConnector extends BaseResolutionPlugIn implements DataConnectorPlugIn {

	private static Logger log = Logger.getLogger(JDBCDataConnector.class.getName());
	private Properties props = new Properties();
	private String searchVal = null;
	private String aeClassName = null;

	final private static String QueryAtt = "query";
	final private static String AttributeExtractorAtt = "attributeExtractor";
	final private static String DBDriverAtt = "dbDriver";
	final private static String AEInstanceMethodAtt = "instance";
	final private static String URLAtt = "dbURL";

	public JDBCDataConnector(Element e) throws ResolutionPlugInException {

		super(e);

		NodeList propertiesNode = e.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "Property");
		NodeList searchNode = e.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "Search");

		/**
		 * Gets and sets the search parameter and the attribute extractor
		 */
		searchVal = ((Element) searchNode.item(0)).getAttribute(QueryAtt);
		aeClassName = ((Element) searchNode.item(0)).getAttribute(AttributeExtractorAtt);

		if (searchVal == null || searchVal.equals("")) {
			log.error("Search requires a specified query field");
			throw new ResolutionPlugInException("mySQLDataConnection requires a \"Search\" specification");
		} else {
			log.debug("Search Query: (" + searchVal + ")");
		}

		/**
		 * Assigns the property attribute name/value pairs to a hashtable
		 */
		for (int i = 0; propertiesNode.getLength() > i; i++) {
			Element property = (Element) propertiesNode.item(i);
			String propertiesName = property.getAttribute("name");
			String propertiesValue = property.getAttribute("value");

			if (propertiesName != null
				&& !propertiesName.equals("")
				&& propertiesValue != null
				&& !propertiesValue.equals("")) {
				props.setProperty(propertiesName, propertiesValue);
				log.debug("Property: (" + propertiesName + ")");
				log.debug("   Value: (" + propertiesValue + ")");
			} else {
				log.error("Property is malformed.");
				throw new ResolutionPlugInException("Property is malformed.");
			}
		}
        
        if (props.getProperty(URLAtt) == null) {
            log.error("JDBC connection requires a dbURL property");
            throw new ResolutionPlugInException("JDBCDataConnection requires a \"dbURL\" property");
        }
	}

	public Attributes resolve(Principal principal) throws ResolutionPlugInException {
		Connection conn = null;
		ResultSet rs = null;
		JDBCAttributeExtractor aeClassObj = null;

		log.debug("Resolving connector: (" + getId() + ")");
		log.debug(getId() + " resolving for principal: (" + principal.getName() + ")");

		//Replaces %PRINCIPAL% in the query string with its value
		log.debug("The query string before coverting %PRINCIPAL%: " + searchVal);
		String convertedSearchVal = searchVal.replaceAll("%PRINCIPAL%", principal.getName());
		log.debug("The query string after converting %PRINCIPAL%: " + convertedSearchVal);

		try {
			//Loads the database driver
			loadDriver((String) props.get(DBDriverAtt));
		} catch (ClassNotFoundException e) {
			log.error("An ClassNotFoundException occured while loading database driver");
			throw new ResolutionPlugInException(
				"An ClassNotFoundException occured while loading database driver: " + e.getMessage());
		} catch (IllegalAccessException e) {
			log.error("An IllegalAccessException occured while loading database driver");
			throw new ResolutionPlugInException(
				"An IllegalAccessException occured while loading database driver: " + e.getMessage());
		} catch (InstantiationException e) {
			log.error("An InstantionException occured while loading database driver");
			throw new ResolutionPlugInException(
				"An InstantiationException occured while loading database driver: " + e.getMessage());
		}

		try {
			//Makes the connection to the database
			conn = connect();
		} catch (SQLException e) {
			log.error("An ERROR occured while connecting to database");
			throw new ResolutionPlugInException("An ERROR occured while connecting to the database: " + e.getMessage());
		}

		try {
			//Gets the results set for the query
			rs = executeQuery(conn, convertedSearchVal);
		} catch (SQLException e) {
			log.error("An ERROR occured while executing the query");
			throw new ResolutionPlugInException("An ERROR occured while executing the query: " + e.getMessage());
		}

		/**
		 * If the user has supplied their own class for extracting the attributes from the 
		 * result set, then their class will be run.  A BasicAttributes object is expected as
		 * the result of the extraction.
		 *
		 * If the user has no supplied their own class for extracting the attributes then 
		 * the default extraction is run, which is specified in DefaultAEAtt.
		 */
		if (aeClassName == null || aeClassName.equals("")) {
			aeClassName = DefaultAE.class.getName();
		}

		try {
			Class aeClass = Class.forName(aeClassName);
			Method aeMethod = aeClass.getMethod(AEInstanceMethodAtt, null);

			//runs the "instance" method returning and instance of the object
			aeClassObj = (JDBCAttributeExtractor) (aeMethod.invoke(null, null));
			log.debug("Supplied attributeExtractor class loaded.");

		} catch (ClassNotFoundException e) {
			log.error("The supplied attribute extractor class could not be found");
			throw new ResolutionPlugInException(
				"The supplied attribute extractor class could not be found: " + e.getMessage());
		} catch (NoSuchMethodException e) {
			log.error("The requested method does not exist");
			throw new ResolutionPlugInException("The requested method does not exist: " + e.getMessage());
		} catch (IllegalAccessException e) {
			log.error("Access is not permitted for invoking requested method");
			throw new ResolutionPlugInException(
				"Access is not permitted for invoking requested method: " + e.getMessage());
		} catch (InvocationTargetException e) {
			log.error("An ERROR occured invoking requested method");
			throw new ResolutionPlugInException("An ERROR occured involking requested method: " + e.getMessage());
		}

		try {
			return aeClassObj.extractAttributes(rs);

		} catch (JDBCAttributeExtractorException e) {
			log.error("An ERROR occured while extracting attributes from result set");
			throw new ResolutionPlugInException(
				"An ERROR occured while extracting attributes from result set: " + e.getMessage());
		} finally {
			try {
				//release result set
				rs.close();
				log.debug("Result set released");
			} catch (SQLException e) {
				log.error("An error occured while closing the result set: " + e);
				throw new ResolutionPlugInException("An error occured while closing the result set: " + e);
			}

			try {
				//close the connection
				conn.close();
				log.debug("Connection to database closed");
			} catch (SQLException e) {
				log.error("An error occured while closing the database connection: " + e);
				throw new ResolutionPlugInException("An error occured while closing the database connection: " + e);
			}
		}
	}

	/** 
	 * Loads the driver used to access the database
	 * @param driver The driver used to access the database
	 * @throws ResolutionPlugInException If there is a failure to load the driver
	 */
	public void loadDriver(String driver)
		throws ClassNotFoundException, IllegalAccessException, InstantiationException {
		Class.forName(driver).newInstance();
		log.debug("Loading driver: " + driver);
	}

	/** 
	 * Makes a connection to the database using the property set.
	 * @return Connection object
	 * @throws SQLException If there is a failure to make a database connection
	 */
	public Connection connect()
		throws SQLException {
        String url = props.getProperty(URLAtt);
		log.debug(url);
		Connection conn = DriverManager.getConnection(url,props);
		log.debug("Connection with database established");

		return conn;
	}

	/**
	 * Execute the users query
	 * @param query The query the user wishes to execute
	 * @return The result of the users <code>query</code>
	 * @return null if an error occurs during execution
	 * @throws SQLException If an error occurs while executing the query
	*/
	public ResultSet executeQuery(Connection conn, String query) throws SQLException {
		log.debug("Users Query: " + query);
		Statement stmt = conn.createStatement();
		return stmt.executeQuery(query);
	}
}

/**
 * The default attribute extractor. 
 */

class DefaultAE implements JDBCAttributeExtractor {
	private static DefaultAE _instance = null;
	private static Logger log = Logger.getLogger(DefaultAE.class.getName());

	// Constructor
	protected DefaultAE() {
	}

	// Ensures that only one istance of the class at a time
	public static DefaultAE instance() {
		if (_instance == null)
			return new DefaultAE();
		else
			return _instance;
	}

	/**
	 * Method of extracting the attributes from the supplied result set.
	 *
	 * @param ResultSet The result set from the query which contains the attributes
	 * @return BasicAttributes as objects containing all the attributes
	 * @throws JDBCAttributeExtractorException If there is a complication in retrieving the attributes
	 */
	public BasicAttributes extractAttributes(ResultSet rs) throws JDBCAttributeExtractorException {
		BasicAttributes attributes = new BasicAttributes();

		log.debug("Using default Attribute Extractor");

		try {
                // No rows returned...
                if (!rs.next())
                return attributes;
		}
        catch (SQLException e) {
			log.error("An error occured while accessing result set");
			throw new JDBCAttributeExtractorException(
				"An error occured while accessing result set: " + e.getMessage());
		}

		try {
            ResultSetMetaData rsmd = rs.getMetaData();
			int numColumns = rsmd.getColumnCount();
			log.debug("Number of returned columns: " + numColumns);

			for (int i = 1; i <= numColumns; i++) {
				String columnName = rsmd.getColumnName(i);
				String columnType = rsmd.getColumnTypeName(i);
				Object columnValue = rs.getObject(columnName);
				log.debug(
					"(" + i + ". ColumnType = " + columnType + ") " + columnName + " -> " + (columnValue!=null ? columnValue.toString() : "(null)"));
				attributes.put(new BasicAttribute(columnName, columnValue));
			}
		}
        catch (SQLException e) {
			log.error("An ERROR occured while retrieving result set meta data");
			throw new JDBCAttributeExtractorException(
				"An ERROR occured while retrieving result set meta data: " + e.getMessage());
		}

        // Check for multiple rows.
        try {
            if (rs.next())
                throw new JDBCAttributeExtractorException("Query returned more than one row.");
        }
        catch (SQLException e) {
        }

		return attributes;
	}
}
