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

import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.security.Principal;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Iterator;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.sql.DataSource;

import org.apache.commons.dbcp.ConnectionFactory;
import org.apache.commons.dbcp.DriverManagerConnectionFactory;
import org.apache.commons.dbcp.PoolableConnectionFactory;
import org.apache.commons.dbcp.PoolingDataSource;
import org.apache.commons.pool.ObjectPool;
import org.apache.commons.pool.impl.GenericObjectPool;
import org.apache.log4j.Logger;
import org.apache.log4j.Priority;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeResolver;
import edu.internet2.middleware.shibboleth.aa.attrresolv.DataConnectorPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugInException;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttribute;

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
	protected Properties props = new Properties();
	protected String searchVal;
	protected DataSource dataSource;
	protected JDBCAttributeExtractor extractor;

	public JDBCDataConnector(Element element) throws ResolutionPlugInException {

		super(element);

		//Get the query string
		NodeList searchNode = element.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "Search");
		searchVal = ((Element) searchNode.item(0)).getAttribute("query");

		if (searchVal == null || searchVal.equals("")) {
			Node tnode = searchNode.item(0).getFirstChild();
			if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
				searchVal = tnode.getNodeValue();
			}
			if (searchVal == null || searchVal.equals("")) {
				log.error("Search requires a specified query field");
				//TODO stinky error message
				throw new ResolutionPlugInException("mySQLDataConnection requires a \"Search\" specification");
			}
		} else {
			log.debug("Search Query: (" + searchVal + ")");
		}

		//Instantiate an attribute extractor, using the default if none is specified
		String aeClassName = ((Element) searchNode.item(0)).getAttribute("attributeExtractor");
		if (aeClassName == null || aeClassName.equals("")) {
			aeClassName = DefaultAE.class.getName();
		}
		try {
			Class aeClass = Class.forName(aeClassName);
			Constructor constructor = aeClass.getConstructor(null);
			extractor = (JDBCAttributeExtractor) constructor.newInstance(null);
			log.debug("Supplied attributeExtractor class loaded.");

		} catch (ClassNotFoundException e) {
			log.error("The supplied Attribute Extractor class could not be found: " + e);
			throw new ResolutionPlugInException(
				"The supplied Attribute Extractor class could not be found: " + e.getMessage());
		} catch (Exception e) {
			log.error("Unable to instantiate Attribute Extractor implementation: " + e);
			throw new ResolutionPlugInException(
				"Unable to instantiate Attribute Extractor implementation: " + e.getMessage());
		}

		//Grab all other properties
		NodeList propertiesNode = element.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "Property");
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

		if (props.getProperty("dbURL") == null) {
			log.error("JDBC connection requires a dbURL property");
			throw new ResolutionPlugInException("JDBCDataConnection requires a \"dbURL\" property");
		}

		//Load the supplied JDBC driver
		loadDriver((String) props.get("dbDriver"));
		
		//Setup the Pool
		GenericObjectPool genericObjectPool = new GenericObjectPool(null);

		try {
			if (props.getProperty("maxActiveConnections") != null) {
				genericObjectPool.setMaxActive(Integer.parseInt(props.getProperty("maxActiveConnections")));
			}
			if (props.getProperty("maxIdleConnections") != null) {
				genericObjectPool.setMaxIdle(Integer.parseInt(props.getProperty("maxIdleConnections")));
			}
		} catch (NumberFormatException e) {
			log.error("Malformed pooling configuration settings: using defaults.");
		}
		genericObjectPool.setWhenExhaustedAction(GenericObjectPool.WHEN_EXHAUSTED_BLOCK);

		ObjectPool connPool = genericObjectPool;
		ConnectionFactory connFactory = null;
		PoolableConnectionFactory poolConnFactory = null;

		try {
			connFactory = new DriverManagerConnectionFactory(props.getProperty("dbURL"), null);
			log.debug("Connection factory initialized.");
		} catch (Exception ex) {
			log.error(
				"Connection factory couldn't be initialized, ensure database URL, username and password are correct.");
			throw new ResolutionPlugInException("Connection facotry couldn't be initialized: " + ex.getMessage());
		}

		try {
			poolConnFactory = new PoolableConnectionFactory(connFactory, connPool, null, null, false, true);
		} catch (Exception ex) {
			log.debug("Poolable connection factory error");
		}

		dataSource = new PoolingDataSource(connPool);
		try {
			dataSource.setLogWriter(
				new Log4jPrintWriter(Logger.getLogger(JDBCDataConnector.class.getName() + ".Pool"), Priority.DEBUG));
		} catch (SQLException e) {
			log.error("Coudn't setup logger for database connection pool.");
		}
	}

	protected String substitute(String source, String pattern, boolean quote, Dependencies depends) {
		Matcher m = Pattern.compile(pattern).matcher(source);
		while (m.find()) {
			String field = source.substring(m.start() + 1, m.end() - 1);
			if (field != null && field.length() > 0) {
				StringBuffer buf = new StringBuffer();

				//Look for an attribute dependency.
				ResolverAttribute dep = depends.getAttributeResolution(field);
				if (dep != null) {
					Iterator iter = dep.getValues();
					while (iter.hasNext()) {
						if (buf.length() > 0)
							buf = buf.append(',');
						if (quote)
							buf = buf.append("'");
						buf = buf.append(iter.next());
						if (quote)
							buf = buf.append("'");
					}
				}

				//If no values found, cycle over the connectors.
				Iterator connDeps = connectorDependencyIds.iterator();
				while (buf.length() == 0 && connDeps.hasNext()) {
					Attributes attrs = depends.getConnectorResolution((String) connDeps.next());
					if (attrs != null) {
						Attribute attr = attrs.get(field);
						if (attr != null) {
							try {
								NamingEnumeration vals = attr.getAll();
								while (vals.hasMore()) {
									if (buf.length() > 0)
										buf = buf.append(',');
									if (quote)
										buf = buf.append("'");
									buf = buf.append(vals.next());
									if (quote)
										buf = buf.append("'");
								}
							} catch (NamingException e) {
								// Auto-generated catch block
							}
						}
					}
				}

				if (buf.length() == 0) {
					log.warn(
						"Unable to find any values to substitute in query for "
							+ field
							+ ", so using the empty string");
				}
				source = source.replaceAll(m.group(), buf.toString());
				m.reset(source);
			}
		}
		return source;
	}

	public Attributes resolve(Principal principal, String requester, Dependencies depends)
		throws ResolutionPlugInException {

		log.debug("Resolving connector: (" + getId() + ")");
		log.debug(getId() + " resolving for principal: (" + principal.getName() + ")");
		log.debug("The query string before inserting substitutions: " + searchVal);

		//Replaces %PRINCIPAL% in the query string with its value
		String convertedSearchVal = searchVal.replaceAll("%PRINCIPAL%", principal.getName());
		convertedSearchVal = convertedSearchVal.replaceAll("@PRINCIPAL@", "'" + principal.getName() + "'");

		//Find all delimited substitutions and replace with the named attribute value(s).
		convertedSearchVal = substitute(convertedSearchVal, "%.+%", false, depends);
		convertedSearchVal = substitute(convertedSearchVal, "@.+@", true, depends);

		//Replace any escaped substitution delimiters.
		convertedSearchVal = convertedSearchVal.replaceAll("\\%", "%");
		convertedSearchVal = convertedSearchVal.replaceAll("\\@", "@");

		log.debug("The query string after inserting substitutions: " + convertedSearchVal);

		/**
		 * Retrieves a connection from the connection pool
		 */
		Connection conn = null;
		try {
			conn = dataSource.getConnection();
			log.debug("Connection retrieved from pool");
		} catch (Exception e) {
			log.error("Unable to fetch a connection from the pool");
			throw new ResolutionPlugInException("Unable to fetch a connection from the pool: " + e.getMessage());
		}
		if (conn == null) {
			log.error("Pool didn't return a propertly initialized connection.");
			throw new ResolutionPlugInException("Pool didn't return a propertly initialized connection.");
		}

		ResultSet rs = null;
		try {
			//Gets the results set for the query
			rs = executeQuery(conn, convertedSearchVal);
			if (!rs.next())
				return new BasicAttributes();

		} catch (SQLException e) {
			log.error("An ERROR occured while executing the query");
			throw new ResolutionPlugInException("An ERROR occured while executing the query: " + e.getMessage());
		}

		try {
			return extractor.extractAttributes(rs);

		} catch (JDBCAttributeExtractorException e) {
			log.error("An ERROR occured while extracting attributes from result set");
			throw new ResolutionPlugInException(
				"An ERROR occured while extracting attributes from result set: " + e.getMessage());
		} finally {
			try {
				rs.close();
			} catch (SQLException e) {
				log.error("An error occured while closing the result set: " + e);
				throw new ResolutionPlugInException("An error occured while closing the result set: " + e);
			}

			try {
				conn.close();
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
	public void loadDriver(String driver) throws ResolutionPlugInException {
		try {
			Class.forName(driver).newInstance();
			log.debug("Loading JDBC driver: " + driver);
		} catch (Exception e) {
			log.error("An error loading database driver: " + e);
			throw new ResolutionPlugInException(
				"An IllegalAccessException occured while loading database driver: " + e.getMessage());
		}
		log.debug("Driver loaded.");
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

	private class Log4jPrintWriter extends PrintWriter {

		private Priority level;
		private Logger logger;
		private StringBuffer text = new StringBuffer("");

		private Log4jPrintWriter(Logger logger, org.apache.log4j.Priority level) {
			super(System.err);
			this.level = level;
			this.logger = logger;
		}

		public void close() {
			flush();
		}

		public void flush() {
			if (!text.toString().equals("")) {
				logger.log(level, text.toString());
				text.setLength(0);
			}
		}

		public void print(boolean b) {
			text.append(b);
		}

		public void print(char c) {
			text.append(c);
		}

		public void print(char[] s) {
			text.append(s);
		}

		public void print(double d) {
			text.append(d);
		}

		public void print(float f) {
			text.append(f);
		}

		public void print(int i) {
			text.append(i);
		}

		public void print(long l) {
			text.append(l);
		}

		public void print(Object obj) {
			text.append(obj);
		}

		public void print(String s) {
			text.append(s);
		}

		public void println() {
			if (!text.toString().equals("")) {
				logger.log(level, text.toString());
				text.setLength(0);
			}
		}

		public void println(boolean x) {
			text.append(x);
			logger.log(level, text.toString());
			text.setLength(0);
		}

		public void println(char x) {
			text.append(x);
			logger.log(level, text.toString());
			text.setLength(0);
		}

		public void println(char[] x) {
			text.append(x);
			logger.log(level, text.toString());
			text.setLength(0);
		}

		public void println(double x) {
			text.append(x);
			logger.log(level, text.toString());
			text.setLength(0);
		}

		public void println(float x) {
			text.append(x);
			logger.log(level, text.toString());
			text.setLength(0);
		}

		public void println(int x) {
			text.append(x);
			logger.log(level, text.toString());
			text.setLength(0);
		}

		public void println(long x) {
			text.append(x);
			logger.log(level, text.toString());
			text.setLength(0);
		}

		public void println(Object x) {
			text.append(x);
			logger.log(level, text.toString());
			text.setLength(0);
		}

		public void println(String x) {
			text.append(x);
			logger.log(level, text.toString());
			text.setLength(0);
		}
	}
}

/**
 * The default attribute extractor. 
 */

class DefaultAE implements JDBCAttributeExtractor {

	private static Logger log = Logger.getLogger(DefaultAE.class.getName());

	// Constructor
	public DefaultAE() {
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
			ResultSetMetaData rsmd = rs.getMetaData();
			int numColumns = rsmd.getColumnCount();
			log.debug("Number of returned columns: " + numColumns);

			for (int i = 1; i <= numColumns; i++) {
				String columnName = rsmd.getColumnName(i);
				String columnType = rsmd.getColumnTypeName(i);
				Object columnValue = rs.getObject(columnName);
				log.debug(
					"("
						+ i
						+ ". ColumnType = "
						+ columnType
						+ ") "
						+ columnName
						+ " -> "
						+ (columnValue != null ? columnValue.toString() : "(null)"));
				attributes.put(new BasicAttribute(columnName, columnValue));
			}
		} catch (SQLException e) {
			log.error("An ERROR occured while retrieving result set meta data");
			throw new JDBCAttributeExtractorException(
				"An ERROR occured while retrieving result set meta data: " + e.getMessage());
		}

		// Check for multiple rows.
		try {
			if (rs.next())
				throw new JDBCAttributeExtractorException("Query returned more than one row.");
		} catch (SQLException e) {
			//TODO don't squelch this error!!!
		}

		return attributes;
	}
}
