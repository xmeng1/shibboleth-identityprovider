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
import java.util.Hashtable;

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
 * @version 0.1 July 23, 2003
 */

public class JDBCDataConnector extends BaseResolutionPlugIn implements DataConnectorPlugIn {

	private static Logger log = Logger.getLogger(JDBCDataConnector.class.getName());
	private Hashtable env = new Hashtable();
	private String searchVal = null;
	private String aeClassName = null;

	final private static String QueryAtt = "query";
	final private static String AttributeExtractorAtt = "attributeExtractor";
	final private static String DBDriverAtt = "dbDriver";
	final private static String AEInstanceMethodAtt = "instance";
	final private static String DBSubProtocolAtt = "dbSubProtocol";
	final private static String DBHostAtt = "dbHost";
	final private static String DBNameAtt = "dbName";
	final private static String UserNameAtt = "userName";
	final private static String PasswordAtt = "password";

	public JDBCDataConnector(Element e) throws ResolutionPlugInException {

		super(e);

		NodeList propertiesNode = e.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "Property");
		NodeList searchNode = e.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "Search");

		String propertiesName = null;
		String propertiesValue = null;

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
			propertiesName = property.getAttribute("name");
			propertiesValue = property.getAttribute("value");

			if (propertiesName != null
				&& !propertiesName.equals("")
				&& propertiesValue != null
				&& !propertiesValue.equals("")) {
				env.put(propertiesName, propertiesValue);
				log.debug("Property: (" + propertiesName + ")");
				log.debug("   Value: (" + propertiesValue + ")");
			} else {
				log.error("Property is malformed.");
				throw new ResolutionPlugInException("Property is malformed.");
			}
		}
	}

	public Attributes resolve(Principal principal) throws ResolutionPlugInException {
		Connection conn = null;
		ResultSet rs = null;
		ResultSetMetaData rsmd = null;
		BasicAttributes attributes = new BasicAttributes();
		JDBCAttributeExtractor aeClassObj = null;

		log.debug("Resolving connector: (" + getId() + ")");
		log.debug(getId() + " resolving for principal: (" + principal.getName() + ")");

		//Replaces %PRINCIPAL% in the query string with its value
		log.debug("The query string before coverting %PRINCIPAL%: " + searchVal);
		searchVal = searchVal.replaceAll("%PRINCIPAL%", principal.getName());
		log.debug("The query string after converting %PRINCIPAL%: " + searchVal);

		try {
			//Loads the database driver
			loadDriver((String) env.get(DBDriverAtt));
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
			conn =
				connect(
					(String) env.get(DBSubProtocolAtt),
					(String) env.get(DBHostAtt),
					(String) env.get(DBNameAtt),
					(String) env.get(UserNameAtt),
					(String) env.get(PasswordAtt));
		} catch (SQLException e) {
			log.error("An ERROR occured while connecting to database");
			throw new ResolutionPlugInException("An ERROR occured while connecting to the database: " + e.getMessage());
		}

		try {
			//Gets the results set for the query
			rs = executeQuery(conn, searchVal);
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
	 * Makes a connection to the database
	 * @param subProtocal Specifies the sub protocal to use when connecting
	 * @param hostName  The host name for the database
	 * @param dbName The database to access
	 * @param userName The username to connect with
	 * @param password The password to connect with
	 * @return Connection objecet
	 * @throws SQLException If there is a failure to make a database connection
	 */
	public Connection connect(String subProtocol, String hostName, String dbName, String userName, String password)
		throws SQLException {
		log.debug(
			"jdbc:" + subProtocol + "://" + hostName + "/" + dbName + "?user=" + userName + "&password=" + password);
		Connection conn =
			DriverManager.getConnection("jdbc:" + subProtocol + "://" + hostName + "/" + dbName, userName, password);
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
		String columnName = null;
		String columnType = null;
		int numRows = 0, numColumns = 0;
		ResultSetMetaData rsmd = null;
		BasicAttributes attributes = new BasicAttributes();
		Object columnValue = new Object();

		log.debug("Using default Attribute Extractor");

		try {
			rs.last();
			numRows = rs.getRow();
			rs.first();
		} catch (SQLException e) {
			log.error("An ERROR occured while determining result set row size");
			throw new JDBCAttributeExtractorException(
				"An ERROR occured while determining result set row size: " + e.getMessage());
		}

		log.debug("The number of rows returned is: " + numRows);

		if (numRows > 1)
			throw new JDBCAttributeExtractorException("Query returned more than one result set.");

		try {
			rsmd = rs.getMetaData();
			numColumns = rsmd.getColumnCount();
			log.debug("Number of returned columns: " + numColumns);

			for (int i = 1; i <= numColumns; i++) {
				columnName = rsmd.getColumnName(i);
				columnType = rsmd.getColumnTypeName(i);
				columnValue = rs.getObject(columnName);
				log.debug(
					"(" + i + ". ColumnType = " + columnType + ") " + columnName + " -> " + columnValue.toString());
				attributes.put(new BasicAttribute(columnName, columnValue));
			}
		} catch (SQLException e) {
			log.error("An ERROR occured while retrieving result set meta data");
			throw new JDBCAttributeExtractorException(
				"An ERROR occured while retrieving result set meta data: " + e.getMessage());
		}

		return attributes;
	}
}
