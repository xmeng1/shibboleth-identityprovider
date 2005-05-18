/*
 * Copyright (c) 2003 National Research Council of Canada Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions: The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
 * AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package edu.internet2.middleware.shibboleth.aa.attrresolv.provider;

import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.security.Principal;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Types;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Properties;

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
import org.apache.commons.pool.impl.GenericObjectPool;
import org.apache.commons.pool.impl.StackKeyedObjectPoolFactory;
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
 * <ahref="http://www.cisti-icist.nrc-cnrc.gc.ca/">http://www.cisti-icist.nrc-cnrc.gc.ca/ </a>, the National Research
 * Council Canada (NRC <a href="http://www.nrc-cnrc.gc.ca/">http://www.nrc-cnrc.gc.ca/ </a>) by David Dearman, COOP
 * student from Dalhousie University, under the direction of Glen Newton, Head research (IT)
 * <ahref="mailto:glen.newton@nrc-cnrc.gc.ca">glen.newton@nrc-cnrc.gc.ca </a>.
 */

/**
 * Data Connector that uses JDBC to access user attributes stored in databases.
 * 
 * @author David Dearman (dearman@cs.dal.ca)
 * @author Walter Hoehn (wassa@columbia.edu)
 * @author Scott Cantor
 */

public class JDBCDataConnector extends BaseDataConnector implements DataConnectorPlugIn {

	private static Logger log = Logger.getLogger(JDBCDataConnector.class.getName());
	protected String searchVal;
	protected int minResultSet = 0, maxResultSet = 0, retryInterval = 300;
	protected long deadSince = 0;
	protected DataSource dataSource;
	protected JDBCAttributeExtractor extractor;
	protected JDBCStatementCreator statementCreator;

	public JDBCDataConnector(Element e) throws ResolutionPlugInException {

		super(e);

		// Get the query string
		NodeList queryNodes = e.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "Query");
		Node tnode = queryNodes.item(0).getFirstChild();
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			searchVal = tnode.getNodeValue();
		}
		if (searchVal == null || searchVal.equals("")) {
			log.error("Database query must be specified.");
			throw new ResolutionPlugInException("Database query must be specified.");
		}

		// Load the supplied JDBC driver
		String dbDriverName = e.getAttribute("dbDriver");
		if (dbDriverName != null && (!dbDriverName.equals(""))) {
			loadDriver(dbDriverName);
		}

		String validationQuery = e.getAttribute("validationQuery");
		if (validationQuery == null || validationQuery.equals("")) {
			validationQuery = "select 1";
		}

		try {
			if (e.getAttributeNode("minResultSet") != null) {
				minResultSet = Integer.parseInt(e.getAttribute("minResultSet"));
			}
			if (e.getAttributeNode("maxResultSet") != null) {
				maxResultSet = Integer.parseInt(e.getAttribute("maxResultSet"));
			}
			if (e.getAttributeNode("retryInterval") != null) {
				retryInterval = Integer.parseInt(e.getAttribute("retryInterval"));
			}
		} catch (NumberFormatException ex) {
			log.error("Malformed result set and retry limits: using defaults.");
		}

		// Load site-specific implementation classes
		setupAttributeExtractor((Element) e.getElementsByTagNameNS(AttributeResolver.resolverNamespace,
				"AttributeExtractor").item(0));
		setupStatementCreator((Element) e.getElementsByTagNameNS(AttributeResolver.resolverNamespace,
				"StatementCreator").item(0));

		// Load driver properties
		Properties props = new Properties();
		NodeList propertiesNode = e.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "Property");
		for (int i = 0; propertiesNode.getLength() > i; i++) {
			Element property = (Element) propertiesNode.item(i);
			String propertiesName = property.getAttribute("name");
			String propertiesValue = property.getAttribute("value");

			if (propertiesName != null && !propertiesName.equals("") && propertiesValue != null
					&& !propertiesValue.equals("")) {
				props.setProperty(propertiesName, propertiesValue);
				log.debug("Property: (" + propertiesName + ")");
				log.debug("   Value: (" + propertiesValue + ")");
			} else {
				log.error("Property is malformed.");
				throw new ResolutionPlugInException("Property is malformed.");
			}
		}

		// Initialize a pooling Data Source
		int maxActive = 5;
		int maxIdle = 5;
		int maxWait = 15;
		try {
			if (e.getAttributeNode("maxActive") != null) {
				maxActive = Integer.parseInt(e.getAttribute("maxActive"));
			}
			if (e.getAttributeNode("maxIdle") != null) {
				maxIdle = Integer.parseInt(e.getAttribute("maxIdle"));
			}
			if (e.getAttributeNode("maxWait") != null) {
				maxWait = Integer.parseInt(e.getAttribute("maxWait"));
			}
		} catch (NumberFormatException ex) {
			log.error("Malformed pooling limits: using defaults.");
		}
		if (e.getAttribute("dbURL") == null || e.getAttribute("dbURL").equals("")) {
			log.error("JDBC connection requires a dbURL property");
			throw new ResolutionPlugInException("JDBCDataConnection requires a \"dbURL\" property");
		}
		setupDataSource(e.getAttribute("dbURL"), props, maxActive, maxIdle, maxWait, validationQuery);
	}

	/**
	 * Initialize a Pooling Data Source
	 */
	private void setupDataSource(String dbURL, Properties props, int maxActive, int maxIdle, int maxWait,
			String validationQuery) throws ResolutionPlugInException {

		GenericObjectPool objectPool = new GenericObjectPool(null);

		objectPool.setMaxActive(maxActive);
		objectPool.setMaxIdle(maxIdle);
		if (maxWait > 0) objectPool.setMaxWait(1000 * maxWait);
		else objectPool.setMaxWait(maxWait);

		objectPool.setWhenExhaustedAction(GenericObjectPool.WHEN_EXHAUSTED_BLOCK);
		objectPool.setTestOnBorrow(true);

		ConnectionFactory connFactory = null;
		PoolableConnectionFactory poolConnFactory = null;

		try {
			connFactory = new DriverManagerConnectionFactory(dbURL, props);
			log.debug("Connection factory initialized.");
		} catch (Exception ex) {
			log
					.error("Connection factory couldn't be initialized, ensure database URL, username and password are correct.");
			throw new ResolutionPlugInException("Connection factory couldn't be initialized: " + ex.getMessage());
		}

		try {
			poolConnFactory = new PoolableConnectionFactory(connFactory, objectPool, new StackKeyedObjectPoolFactory(),
					validationQuery, true, true);
		} catch (Exception ex) {
			log.debug("Poolable connection factory error");
		}

		dataSource = new PoolingDataSource(objectPool);
		log.info("Data Source initialized.");
		try {
			dataSource.setLogWriter(new Log4jPrintWriter(Logger.getLogger(JDBCDataConnector.class.getName() + ".Pool"),
					Priority.DEBUG));
		} catch (SQLException e) {
			log.error("Coudn't setup logger for database connection pool.");
		}
	}

	/**
	 * Instantiate an Attribute Extractor, using the default if none was configured
	 */
	private void setupAttributeExtractor(Element config) throws ResolutionPlugInException {

		String className = null;
		if (config != null) {
			className = config.getAttribute("class");
		}
		if (className == null || className.equals("")) {
			log.debug("Using default Attribute Extractor.");
			className = DefaultAE.class.getName();
		}
		try {
			Class aeClass = Class.forName(className);
			extractor = (JDBCAttributeExtractor) aeClass.newInstance();
			log.debug("Attribute Extractor implementation loaded.");

		} catch (ClassNotFoundException e) {
			log.error("The supplied Attribute Extractor class could not be found: " + e);
			throw new ResolutionPlugInException("The supplied Attribute Extractor class could not be found: "
					+ e.getMessage());
		} catch (Exception e) {
			log.error("Unable to instantiate Attribute Extractor implementation: " + e);
			throw new ResolutionPlugInException("Unable to instantiate Attribute Extractor implementation: "
					+ e.getMessage());
		}
	}

	/**
	 * Instantiate a Statement Creator, using the default if none was configured
	 */
	private void setupStatementCreator(Element config) throws ResolutionPlugInException {

		String scClassName = null;
		if (config != null) {
			scClassName = config.getAttribute("class");
		}
		if (scClassName == null || scClassName.equals("")) {
			log.debug("Using default Statement Creator.");
			scClassName = DefaultStatementCreator.class.getName();
		}
		try {
			Class scClass = Class.forName(scClassName);

			Class[] params = new Class[1];
			params[0] = Class.forName("org.w3c.dom.Element");
			try {
				Constructor implementorConstructor = scClass.getConstructor(params);
				Object[] args = new Object[1];
				args[0] = config;
				log.debug("Initializing Statement Creator of type (" + scClass.getName() + ").");
				statementCreator = (JDBCStatementCreator) implementorConstructor.newInstance(args);
			} catch (NoSuchMethodException nsme) {
				log
						.debug("Implementation constructor does have a parameterized constructor, attempting to load default.");
				statementCreator = (JDBCStatementCreator) scClass.newInstance();
			}
			log.debug("Statement Creator implementation loaded.");

		} catch (ClassNotFoundException e) {
			log.error("The supplied Statement Creator class could not be found: " + e);
			throw new ResolutionPlugInException("The supplied Statement Creator class could not be found: "
					+ e.getMessage());
		} catch (Exception e) {
			log.error("Unable to instantiate Statement Creator implementation: " + e);
			throw new ResolutionPlugInException("Unable to instantiate Statement Creator implementation: "
					+ e.getMessage());
		}
	}

	public Attributes resolve(Principal principal, String requester, Dependencies depends)
			throws ResolutionPlugInException {

		log.debug("Resolving connector: (" + getId() + ")");

		// Are we alive?
		boolean alive = true;
		long now = System.currentTimeMillis();
		synchronized (this) {
			if (deadSince > 0 && now - deadSince < (1000 * retryInterval)) {
				alive = false;
			} else {
				deadSince = 0;
			}
		}

		if (!alive) {
			log.info("JDBC Connector (" + getId() + ") is dead, returning immediately");
			throw new ResolutionPlugInException("Connection is dead");
		}

		// Retrieve a connection from the connection pool
		Connection conn = null;
		try {
			conn = dataSource.getConnection();
			log.debug("Connection retrieved from pool");
		} catch (Exception e) {
			synchronized (this) {
				deadSince = now;
			}
			log.error("JDBC Connector (" + getId() + ") unable to fetch a connection from the pool, marking it dead");
			throw new ResolutionPlugInException("Unable to fetch a connection from the pool, marking it dead: "
					+ e.getMessage());
		}
		if (conn == null) {
			log.error("Pool didn't return a properly initialized connection.");
			throw new ResolutionPlugInException("Pool didn't return a properly initialized connection.");
		}

		// Setup and execute a (pooled) prepared statement
		ResultSet rs = null;
		PreparedStatement preparedStatement = null;
		try {
			preparedStatement = conn.prepareStatement(searchVal);
			preparedStatement.clearParameters();
			statementCreator.create(preparedStatement, principal, requester, depends);
			rs = preparedStatement.executeQuery();
			if (!rs.next()) {
				if (minResultSet == 0) return new BasicAttributes();
				else {
					log.error("Statement returned no rows, violating minResultSet of " + minResultSet);
					throw new ResolutionPlugInException("Statement didn't return any rows, violating minResultSet of "
							+ minResultSet);
				}
			}
			return extractor.extractAttributes(rs, minResultSet, maxResultSet);
		} catch (JDBCStatementCreatorException e) {
			log.error("An ERROR occured while constructing the query");
			throw new ResolutionPlugInException("An ERROR occured while constructing the query: " + e.getMessage());
		} catch (JDBCAttributeExtractorException e) {
			log.error("An ERROR occured while extracting attributes from result set");
			throw new ResolutionPlugInException("An ERROR occured while extracting attributes from result set: "
					+ e.getMessage());
		} catch (SQLException e) {
			synchronized (this) {
				deadSince = now;
			}
			log.error("An ERROR occured while executing the query, marking connector dead");
			throw new ResolutionPlugInException("An ERROR occured while executing the query, marking connector dead: "
					+ e.getMessage());
		} finally {
			Exception e_save = null;
			try {
				if (preparedStatement != null) {
					preparedStatement.close();
				}
			} catch (SQLException e) {
				log.error("An error occured while closing the prepared statement: " + e.getMessage());
				e_save = e;
			}
			try {
				if (rs != null) {
					rs.close();
				}
			} catch (SQLException e) {
				log.error("An error occured while closing the result set: " + e.getMessage());
				e_save = e;
			}
			try {
				conn.close();
			} catch (SQLException e) {
				log.error("An error occured while closing the database connection: " + e.getMessage());
				e_save = e;
			}
			if (e_save != null) { throw new ResolutionPlugInException(
					"An error occured while closing database objects:" + e_save.getMessage()); }
		}
	}

	/**
	 * Loads the driver used to access the database
	 * 
	 * @param driver
	 *            The driver used to access the database
	 * @throws ResolutionPlugInException
	 *             If there is a failure to load the driver
	 */
	public void loadDriver(String driver) throws ResolutionPlugInException {

		try {
			Class.forName(driver).newInstance();
			log.debug("Loading JDBC driver: " + driver);
		} catch (Exception e) {
			log.error("An error loading database driver: " + e);
			throw new ResolutionPlugInException("An IllegalAccessException occured while loading database driver: "
					+ e.getMessage());
		}
		log.debug("Driver loaded.");
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

	public Attributes extractAttributes(ResultSet rs, int minResultSet, int maxResultSet)
			throws JDBCAttributeExtractorException {

		BasicAttributes attributes = new BasicAttributes(true);
		int row = 0;

		try {
			// Get metadata about result set.
			ResultSetMetaData rsmd = rs.getMetaData();
			int numColumns = rsmd.getColumnCount();
			log.debug("Number of returned columns: " + numColumns);

			do {
				if (maxResultSet > 0 && row + 1 > maxResultSet) {
					log.error("Statement returned too many rows, violating maxResultSet of " + maxResultSet);
					throw new JDBCAttributeExtractorException(
							"Statement returned too many rows, violating maxResultSet of " + maxResultSet);
				}

				for (int i = 1; i <= numColumns; i++) {
					String columnName = rsmd.getColumnName(i);
					Object columnValue = rs.getObject(columnName);
					if (log.isDebugEnabled()) {
						log.debug("(" + i + ". ColumnType = " + rsmd.getColumnTypeName(i) + ") " + columnName + " -> "
								+ (columnValue != null ? columnValue.toString() : "(null)"));
					}
					if (row == 0) {
						BasicAttribute ba = new BasicAttribute(columnName, true);
						ba.add(row, columnValue);
						attributes.put(ba);
					} else {
						attributes.get(columnName).add(row, columnValue);
					}
				}
				row++;
			} while (rs.next());
		} catch (SQLException e) {
			log.error("An ERROR occured while processing result set");
			throw new JDBCAttributeExtractorException("An ERROR occured while processing result set: " + e.getMessage());
		}

		if (row < minResultSet) {
			log.error("Statement returned " + row + " rows, violating minResultSet of " + minResultSet);
			throw new JDBCAttributeExtractorException("Statement returned " + row + " rows, violating minResultSet of "
					+ minResultSet);
		}
		return attributes;
	}
}

class DefaultStatementCreator implements JDBCStatementCreator {

	private static Logger log = Logger.getLogger(DefaultStatementCreator.class.getName());

	public void create(PreparedStatement preparedStatement, Principal principal, String requester, Dependencies depends)
			throws JDBCStatementCreatorException {

		try {
			log.debug("Creating prepared statement.  Substituting principal: (" + principal.getName() + ")");
			preparedStatement.setString(1, principal.getName());
			// Tried using ParameterMetaData to determine param count, but it fails, so...
			try {
				int i = 2;
				while (true) {
					preparedStatement.setString(i++, principal.getName());
				}
			} catch (SQLException e) {
				// Ignore any additional exceptions, assume parameters simply don't exist.
			}
		} catch (SQLException e) {
			log.error("Encountered an error while creating prepared statement: " + e);
			throw new JDBCStatementCreatorException("Encountered an error while creating prepared statement: "
					+ e.getMessage());
		}
	}
}

class DependencyStatementCreator implements JDBCStatementCreator {

	private static Logger log = Logger.getLogger(DependencyStatementCreator.class.getName());
	private ArrayList parameters = new ArrayList();

	public DependencyStatementCreator(Element conf) throws JDBCStatementCreatorException {

		NodeList nodes = conf.getElementsByTagName("Parameter");
		for (int i = 0; i < nodes.getLength(); i++) {
			Element parameter = (Element) nodes.item(i);
			String type = "String";
			if (parameter.getAttribute("type") != null && (!parameter.getAttribute("type").equals(""))) {
				type = parameter.getAttribute("type");
			}

			if (parameter.getAttribute("attributeName") == null || parameter.getAttribute("attributeName").equals("")) {
				log.error("Statement Creator Parameter must reference an attribute by name.");
				throw new JDBCStatementCreatorException(
						"Statement Creator Parameter must reference an attribute by name.");
			}

			if (parameter.getAttribute("connectorId") != null && (!parameter.getAttribute("connectorId").equals(""))) {
				parameters.add(new Parameter(type, parameter.getAttribute("attributeName"), parameter
						.getAttribute("connectorId")));
			} else {
				parameters.add(new Parameter(type, parameter.getAttribute("attributeName")));

			}

			if (parameter.getAttribute("nullMissing") != null && (!parameter.getAttribute("nullMissing").equals(""))) {
				if (parameter.getAttribute("nullMissing").equalsIgnoreCase("FALSE")) {
					((Parameter) parameters.get(i)).setNullMissing(false);
				}
			}
		}
		log.debug("Parameters configured: " + parameters.size());
	}

	public void create(PreparedStatement preparedStatement, Principal principal, String requester, Dependencies depends)
			throws JDBCStatementCreatorException {

		try {
			log.debug("Creating prepared statement.  Substituting values from dependencies.");
			for (int i = 0; i < parameters.size(); i++) {
				((Parameter) parameters.get(i)).setParameterValue(preparedStatement, i + 1, depends, principal,
						requester);
			}

		} catch (Exception e) {
			log.error("Encountered an error while creating prepared statement (principal=" + principal.getName()
					+ "): " + e);
			throw new JDBCStatementCreatorException("Encountered an error while creating prepared statement: "
					+ e.getMessage());
		}
	}

	protected class Parameter {

		private String type;
		private String attributeName;
		private boolean referencesConnector = false;
		private String connectorId;
		private boolean nullMissing = true;

		protected Parameter(String type, String attributeName) throws JDBCStatementCreatorException {

			if ((!type.equalsIgnoreCase("String")) && (!type.equalsIgnoreCase("Integer"))
					&& (!type.equalsIgnoreCase("Byte")) && (!type.equalsIgnoreCase("Double"))
					&& (!type.equalsIgnoreCase("Float")) && (!type.equalsIgnoreCase("Long"))
					&& (!type.equalsIgnoreCase("Short")) && (!type.equalsIgnoreCase("Boolean"))
					&& (!type.equalsIgnoreCase("Date")) && (!type.equalsIgnoreCase("Blob"))
					&& (!type.equalsIgnoreCase("Clob"))) {
				log.error("Unsupported type configured for Statement Creator Parameter.");
				throw new JDBCStatementCreatorException("Unable to load Statement Creator Parameter.");
			}
			this.type = type;
			this.attributeName = attributeName;

			if (attributeName == null) {
				log.error("No (attributeName) attribute specified for Statement Creator Parameter.");
				throw new JDBCStatementCreatorException("Unable to load Statement Creator Parameter.");
			} else if ((attributeName.equals("%PRINCIPAL%") || attributeName.equals("%REQUESTER%"))
					&& !type.equalsIgnoreCase("String")) {
				log.error("The (type) attribute must be set to \"String\" when \"%PRINCIPAL%\" or \"%REQUESTER%\" is "
						+ "used as the (attributeName) for a Statement Creator Parameter.");
				throw new JDBCStatementCreatorException("Unable to load Statement Creator Parameter.");
			}
		}

		protected Parameter(String type, String attributeName, String connectorId) throws JDBCStatementCreatorException {

			this(type, attributeName);
			referencesConnector = true;
			this.connectorId = connectorId;

		}

		protected int getSQLType() {

			if (type.equalsIgnoreCase("String")) {
				return Types.VARCHAR;
			} else if (type.equalsIgnoreCase("Integer")) {
				return Types.INTEGER;
			} else if (type.equalsIgnoreCase("Byte")) {
				return Types.TINYINT;
			} else if (type.equalsIgnoreCase("Double")) {
				return Types.DOUBLE;
			} else if (type.equalsIgnoreCase("Float")) {
				return Types.FLOAT;
			} else if (type.equalsIgnoreCase("Long")) {
				return Types.INTEGER;
			} else if (type.equalsIgnoreCase("Short")) {
				return Types.SMALLINT;
			} else if (type.equalsIgnoreCase("Boolean")) {
				return Types.BOOLEAN;
			} else if (type.equalsIgnoreCase("Date")) {
				return Types.DATE;
			} else if (type.equalsIgnoreCase("Blob")) {
				return Types.BLOB;
			} else if (type.equalsIgnoreCase("Clob")) {
				return Types.CLOB;
			} else {
				return Types.VARCHAR;
			}
		}

		protected void setParameterValue(PreparedStatement preparedStatement, int valueIndex, Dependencies depends,
				Principal principal, String requester) throws JDBCStatementCreatorException {

			// handle values from DataConnectors
			if (referencesConnector) {
				Attributes attributes = depends.getConnectorResolution(connectorId);
				if (attributes == null) {
					log.error("Statement Creator misconfiguration: Connector (" + connectorId
							+ ") is not a dependency of this JDBCDataConnector.");
					throw new JDBCStatementCreatorException("Statement Creator misconfiguration: Connector ("
							+ connectorId + ") is not a dependency of this JDBCDataConnector.");
				}

				Attribute attribute = attributes.get(attributeName);
				if (attribute == null || attribute.size() < 1) {
					if (attributeName.equalsIgnoreCase("%REQUESTER%")) {
						try {
							setSpecificParameter(preparedStatement, valueIndex, requester);
							return;
						} catch (Exception e) {
							log.error("Statement Creator encountered an error while adding the parameter 'Requester': "
									+ e);
							throw new JDBCStatementCreatorException(
									"Statement Creator encountered an error while parameter 'Requester': "
											+ e.getMessage());
						}
					} else if (attributeName.equalsIgnoreCase("%PRINCIPAL%")) {
						try {
							setSpecificParameter(preparedStatement, valueIndex, principal.toString());
							return;
						} catch (Exception e) {
							log.error("Statement Creator encountered an error while adding the parameter 'Requester': "
									+ e);
							throw new JDBCStatementCreatorException(
									"Statement Creator encountered an error while parameter 'Requester': "
											+ e.getMessage());
						}
					} else if (nullMissing) {
						try {
							preparedStatement.setNull(valueIndex, getSQLType());
							return;
						} catch (SQLException e) {
							log
									.error("Encountered a problem while attempting to convert missing attribute value to null parameter.");
						}
					}
					log.error("Cannot parameterize prepared statement: missing dependency value.");
					throw new JDBCStatementCreatorException(
							"Cannot parameterize prepared statement: missing dependency value.");
				}

				if (attribute.size() > 1) {
					log.error("Statement Creator encountered a multivalued dependent attribute.");
					throw new JDBCStatementCreatorException(
							"Statement Creator encountered a multivalued dependent attribute.");
				}

				try {
					setSpecificParameter(preparedStatement, valueIndex, attribute.get());
					return;
				} catch (NamingException e) {
					log.error("Statement Creator encountered an error while extracting attributes "
							+ "from a Data Conector: " + e);
					throw new JDBCStatementCreatorException(
							"Statement Creator encountered an error while extracting attributes from a Data Conector: "
									+ e.getMessage());
				}
			}

			// handle values from AttributeDefinitons
			ResolverAttribute attribute = depends.getAttributeResolution(attributeName);
			if (attribute != null) {
				Iterator iterator = attribute.getValues();
				if (iterator.hasNext()) {
					setSpecificParameter(preparedStatement, valueIndex, iterator.next());
					if (iterator.hasNext()) {
						log.error("Statement Creator encountered a multivalued dependent attribute.");
						throw new JDBCStatementCreatorException(
								"Statement Creator encountered a multivalued dependent attribute.");
					}
					return;
				}
			}
			if (nullMissing) {
				try {
					preparedStatement.setNull(valueIndex, getSQLType());
					return;
				} catch (SQLException e) {
					log.error("Encountered a problem while attempting to convert missing attribute "
							+ "value to null parameter.");
				}
			}
			log.error("Cannot parameterize prepared statement: missing dependency value.");
			throw new JDBCStatementCreatorException("Cannot parameterize prepared statement: missing dependency value.");
		}

		protected void setNullMissing(boolean nullMissing) {

			this.nullMissing = nullMissing;
		}

		private void setSpecificParameter(PreparedStatement preparedStatement, int valueIndex, Object object)
				throws JDBCStatementCreatorException {

			if (object == null) {
				try {
					preparedStatement.setNull(valueIndex, getSQLType());
					return;
				} catch (SQLException e) {
					log
							.error("Encountered a problem while attempting to convert missing attribute value to null parameter.");
					throw new JDBCStatementCreatorException(
							"Encountered a problem while attempting to convert missing attribute value to null parameter.");
				}
			} else if (type.equalsIgnoreCase("String")) {
				setString(preparedStatement, valueIndex, object);
			} else if (type.equalsIgnoreCase("Integer")) {
				setInteger(preparedStatement, valueIndex, object);
			} else if (type.equalsIgnoreCase("Byte")) {
				setByte(preparedStatement, valueIndex, object);
			} else if (type.equalsIgnoreCase("Double")) {
				setDouble(preparedStatement, valueIndex, object);
			} else if (type.equalsIgnoreCase("Float")) {
				setFloat(preparedStatement, valueIndex, object);
			} else if (type.equalsIgnoreCase("Long")) {
				setLong(preparedStatement, valueIndex, object);
			} else if (type.equalsIgnoreCase("Short")) {
				setShort(preparedStatement, valueIndex, object);
			} else if (type.equalsIgnoreCase("Boolean")) {
				setBoolean(preparedStatement, valueIndex, object);
			} else if (type.equalsIgnoreCase("Date")) {
				setDate(preparedStatement, valueIndex, object);
			} else if (type.equalsIgnoreCase("Blob")) {
				setBlob(preparedStatement, valueIndex, object);
			} else if (type.equalsIgnoreCase("Clob")) {
				setClob(preparedStatement, valueIndex, object);
			} else {
				setString(preparedStatement, valueIndex, object);
			}
		}

		private void setClob(PreparedStatement preparedStatement, int valueIndex, Object object)
				throws JDBCStatementCreatorException {

			if (object instanceof Clob) {
				try {
					preparedStatement.setClob(valueIndex, (Clob) object);
					return;
				} catch (SQLException e) {
					log.error("Encountered an error while adding parameter to prepared statement: " + e);
					throw new JDBCStatementCreatorException(
							"Encountered an error while adding parameter to prepared statement: " + e.getMessage());
				}
			}
			log.error("Encountered a dependency with an invalid java type.");
			throw new JDBCStatementCreatorException("Encountered a dependency with an invalid java type.");
		}

		private void setBlob(PreparedStatement preparedStatement, int valueIndex, Object object)
				throws JDBCStatementCreatorException {

			if (object instanceof Blob) {
				try {
					preparedStatement.setBlob(valueIndex, (Blob) object);
					return;
				} catch (SQLException e) {
					log.error("Encountered an error while adding parameter to prepared statement: " + e);
					throw new JDBCStatementCreatorException(
							"Encountered an error while adding parameter to prepared statement: " + e.getMessage());
				}
			}
			log.error("Encountered a dependency with an invalid java type.");
			throw new JDBCStatementCreatorException("Encountered a dependency with an invalid java type.");
		}

		private void setDate(PreparedStatement preparedStatement, int valueIndex, Object object)
				throws JDBCStatementCreatorException {

			if (object instanceof java.sql.Date) {
				try {
					preparedStatement.setDate(valueIndex, (java.sql.Date) object);
					return;
				} catch (SQLException e) {
					log.error("Encountered an error while adding parameter to prepared statement: " + e);
					throw new JDBCStatementCreatorException(
							"Encountered an error while adding parameter to prepared statement: " + e.getMessage());
				}
			} else if (object instanceof java.util.Date) {
				try {
					// If you want to be frustrated by the java class library, look no further...
					preparedStatement.setDate(valueIndex, new java.sql.Date(((java.util.Date) object).getTime()));
					return;
				} catch (SQLException e) {
					log.error("Encountered an error while adding parameter to prepared statement: " + e);
					throw new JDBCStatementCreatorException(
							"Encountered an error while adding parameter to prepared statement: " + e.getMessage());
				}
			} else if (object instanceof Long) {
				try {
					preparedStatement.setDate(valueIndex, new java.sql.Date(((Long) object).longValue()));
					return;
				} catch (SQLException e) {
					log.error("Encountered an error while adding parameter to prepared statement: " + e);
					throw new JDBCStatementCreatorException(
							"Encountered an error while adding parameter to prepared statement: " + e.getMessage());
				}
			} else if (object instanceof String) {
				try {
					preparedStatement.setDate(valueIndex, new java.sql.Date(new SimpleDateFormat().parse(
							(String) object).getTime()));
					return;
				} catch (Exception e) {
					log.error("Encountered an error while adding parameter to prepared statement: " + e);
					throw new JDBCStatementCreatorException(
							"Encountered an error while adding parameter to prepared statement: " + e.getMessage());
				}
			}
			log.error("Encountered a dependency with an invalid java type.");
			throw new JDBCStatementCreatorException("Encountered a dependency with an invalid java type.");
		}

		private void setBoolean(PreparedStatement preparedStatement, int valueIndex, Object object)
				throws JDBCStatementCreatorException {

			if (object instanceof Boolean) {
				try {
					preparedStatement.setBoolean(valueIndex, ((Boolean) object).booleanValue());
					return;
				} catch (SQLException e) {
					log.error("Encountered an error while adding parameter to prepared statement: " + e);
					throw new JDBCStatementCreatorException(
							"Encountered an error while adding parameter to prepared statement: " + e.getMessage());
				}
			} else if (object instanceof String) {
				try {
					preparedStatement.setBoolean(valueIndex, new Boolean((String) object).booleanValue());
					return;
				} catch (Exception e) {
					log.error("Encountered an error while adding parameter to prepared statement: " + e);
					throw new JDBCStatementCreatorException(
							"Encountered an error while adding parameter to prepared statement: " + e.getMessage());
				}
			}
			log.error("Encountered a dependency with an invalid java type.");
			throw new JDBCStatementCreatorException("Encountered a dependency with an invalid java type.");
		}

		private void setShort(PreparedStatement preparedStatement, int valueIndex, Object object)
				throws JDBCStatementCreatorException {

			if (object instanceof Boolean) {
				try {
					preparedStatement.setShort(valueIndex, ((Short) object).shortValue());
					return;
				} catch (SQLException e) {
					log.error("Encountered an error while adding parameter to prepared statement: " + e);
					throw new JDBCStatementCreatorException(
							"Encountered an error while adding parameter to prepared statement: " + e.getMessage());
				}
			} else if (object instanceof String) {
				try {
					preparedStatement.setShort(valueIndex, new Short((String) object).shortValue());
					return;
				} catch (Exception e) {
					log.error("Encountered an error while adding parameter to prepared statement: " + e);
					throw new JDBCStatementCreatorException(
							"Encountered an error while adding parameter to prepared statement: " + e.getMessage());
				}
			}
			log.error("Encountered a dependency with an invalid java type.");
			throw new JDBCStatementCreatorException("Encountered a dependency with an invalid java type.");
		}

		private void setLong(PreparedStatement preparedStatement, int valueIndex, Object object)
				throws JDBCStatementCreatorException {

			if (object instanceof Long || object instanceof Integer || object instanceof Short) {
				try {
					preparedStatement.setLong(valueIndex, ((Number) object).longValue());
					return;
				} catch (SQLException e) {
					log.error("Encountered an error while adding parameter to prepared statement: " + e);
					throw new JDBCStatementCreatorException(
							"Encountered an error while adding parameter to prepared statement: " + e.getMessage());
				}
			} else if (object instanceof String) {
				try {
					preparedStatement.setLong(valueIndex, new Long((String) object).longValue());
					return;
				} catch (Exception e) {
					log.error("Encountered an error while adding parameter to prepared statement: " + e);
					throw new JDBCStatementCreatorException(
							"Encountered an error while adding parameter to prepared statement: " + e.getMessage());
				}
			}
			log.error("Encountered a dependency with an invalid java type.");
			throw new JDBCStatementCreatorException("Encountered a dependency with an invalid java type.");
		}

		private void setFloat(PreparedStatement preparedStatement, int valueIndex, Object object)
				throws JDBCStatementCreatorException {

			if (object instanceof Float) {
				try {
					preparedStatement.setFloat(valueIndex, ((Float) object).floatValue());
					return;
				} catch (SQLException e) {
					log.error("Encountered an error while adding parameter to prepared statement: " + e);
					throw new JDBCStatementCreatorException(
							"Encountered an error while adding parameter to prepared statement: " + e.getMessage());
				}
			} else if (object instanceof String) {
				try {
					preparedStatement.setFloat(valueIndex, new Float((String) object).floatValue());
					return;
				} catch (Exception e) {
					log.error("Encountered an error while adding parameter to prepared statement: " + e);
					throw new JDBCStatementCreatorException(
							"Encountered an error while adding parameter to prepared statement: " + e.getMessage());
				}
			}
			log.error("Encountered a dependency with an invalid java type.");
			throw new JDBCStatementCreatorException("Encountered a dependency with an invalid java type.");
		}

		private void setDouble(PreparedStatement preparedStatement, int valueIndex, Object object)
				throws JDBCStatementCreatorException {

			if (object instanceof Double || object instanceof Float) {
				try {
					preparedStatement.setDouble(valueIndex, ((Number) object).doubleValue());
					return;
				} catch (SQLException e) {
					log.error("Encountered an error while adding parameter to prepared statement: " + e);
					throw new JDBCStatementCreatorException(
							"Encountered an error while adding parameter to prepared statement: " + e.getMessage());
				}
			} else if (object instanceof String) {
				try {
					preparedStatement.setDouble(valueIndex, new Double((String) object).doubleValue());
					return;
				} catch (Exception e) {
					log.error("Encountered an error while adding parameter to prepared statement: " + e);
					throw new JDBCStatementCreatorException(
							"Encountered an error while adding parameter to prepared statement: " + e.getMessage());
				}
			}
			log.error("Encountered a dependency with an invalid java type.");
			throw new JDBCStatementCreatorException("Encountered a dependency with an invalid java type.");
		}

		private void setByte(PreparedStatement preparedStatement, int valueIndex, Object object)
				throws JDBCStatementCreatorException {

			if (object instanceof Byte) {
				try {
					preparedStatement.setByte(valueIndex, ((Byte) object).byteValue());
					return;
				} catch (SQLException e) {
					log.error("Encountered an error while adding parameter to prepared statement: " + e);
					throw new JDBCStatementCreatorException(
							"Encountered an error while adding parameter to prepared statement: " + e.getMessage());
				}
			} else if (object instanceof String) {
				try {
					preparedStatement.setByte(valueIndex, new Byte((String) object).byteValue());
					return;
				} catch (Exception e) {
					log.error("Encountered an error while adding parameter to prepared statement: " + e);
					throw new JDBCStatementCreatorException(
							"Encountered an error while adding parameter to prepared statement: " + e.getMessage());
				}
			}
			log.error("Encountered a dependency with an invalid java type.");
			throw new JDBCStatementCreatorException("Encountered a dependency with an invalid java type.");
		}

		private void setInteger(PreparedStatement preparedStatement, int valueIndex, Object object)
				throws JDBCStatementCreatorException {

			if (object instanceof Integer || object instanceof Short) {
				try {
					preparedStatement.setInt(valueIndex, ((Number) object).intValue());
					return;
				} catch (SQLException e) {
					log.error("Encountered an error while adding parameter to prepared statement: " + e);
					throw new JDBCStatementCreatorException(
							"Encountered an error while adding parameter to prepared statement: " + e.getMessage());
				}
			} else if (object instanceof String) {
				try {
					preparedStatement.setInt(valueIndex, new Integer((String) object).intValue());
					return;
				} catch (Exception e) {
					log.error("Encountered an error while adding parameter to prepared statement: " + e);
					throw new JDBCStatementCreatorException(
							"Encountered an error while adding parameter to prepared statement: " + e.getMessage());
				}
			}
			log.error("Encountered a dependency with an invalid java type.");
			throw new JDBCStatementCreatorException("Encountered a dependency with an invalid java type.");
		}

		private void setString(PreparedStatement preparedStatement, int valueIndex, Object object)
				throws JDBCStatementCreatorException {

			if (object instanceof String) {
				try {
					preparedStatement.setString(valueIndex, (String) object);
					return;
				} catch (SQLException e) {
					log.error("Encountered an error while adding parameter to prepared statement: " + e);
					throw new JDBCStatementCreatorException(
							"Encountered an error while adding parameter to prepared statement: " + e.getMessage());
				}
			}
			log.error("Encountered a dependency with an invalid java type.");
			throw new JDBCStatementCreatorException("Encountered a dependency with an invalid java type.");
		}
	}
}
