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
 * @author Walter Hoehn (wassa@columbia.edu)
 * @author Scott Cantor
 */

public class JDBCDataConnector extends BaseResolutionPlugIn implements DataConnectorPlugIn {

	private static Logger log = Logger.getLogger(JDBCDataConnector.class.getName());
	protected String searchVal;
	protected DataSource dataSource;
	protected JDBCAttributeExtractor extractor;
	protected JDBCStatementCreator statementCreator;
    protected String failover = null;

	public JDBCDataConnector(Element e) throws ResolutionPlugInException {

		super(e);

        NodeList failoverNodes = e.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "FailoverDependency");
        if (failoverNodes.getLength() > 0) {
            failover = ((Element)failoverNodes.item(0)).getAttribute("requires");
        }
		//Get the query string
		NodeList queryNodes = e.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "Query");
		Node tnode = queryNodes.item(0).getFirstChild();
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			searchVal = tnode.getNodeValue();
		}
		if (searchVal == null || searchVal.equals("")) {
			log.error("Database query must be specified.");
			throw new ResolutionPlugInException("Database query must be specified.");
		}

		//Load the supplied JDBC driver
		String dbDriverName = e.getAttribute("dbDriver");
		if (dbDriverName != null && (!dbDriverName.equals(""))) {
			loadDriver(dbDriverName);
		}

		//Load site-specific implementation classes	
		setupAttributeExtractor(
			(Element) e.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "AttributeExtractor").item(
				0));
		setupStatementCreator(
			(Element) e.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "StatementCreator").item(0));
        
        //Load driver properties
        Properties props = new Properties();
        NodeList propertiesNode = e.getElementsByTagNameNS(AttributeResolver.resolverNamespace, "Property");
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
        
		//Initialize a pooling Data Source
		int maxActive = 0;
		int maxIdle = 0;
		try {
			if (e.getAttributeNode("maxActive") != null) {
				maxActive = Integer.parseInt(e.getAttribute("maxActive"));
			}
			if (e.getAttributeNode("maxIdle") != null) {
				maxIdle = Integer.parseInt(e.getAttribute("maxIdle"));
			}
		} catch (NumberFormatException ex) {
			log.error("Malformed pooling limits: using defaults.");
		}
		if (e.getAttribute("dbURL") == null || e.getAttribute("dbURL").equals("")) {
			log.error("JDBC connection requires a dbURL property");
			throw new ResolutionPlugInException("JDBCDataConnection requires a \"dbURL\" property");
		}
		setupDataSource(e.getAttribute("dbURL"), props, maxActive, maxIdle);
	}

	/**
	 * Initialize a Pooling Data Source
	 */
	private void setupDataSource(String dbURL, Properties props, int maxActive, int maxIdle) throws ResolutionPlugInException {

		GenericObjectPool objectPool = new GenericObjectPool(null);

		if (maxActive > 0) {
			objectPool.setMaxActive(maxActive);
		}
		if (maxIdle > 0) {
			objectPool.setMaxIdle(maxIdle);
		}

		objectPool.setWhenExhaustedAction(GenericObjectPool.WHEN_EXHAUSTED_BLOCK);

		ConnectionFactory connFactory = null;
		PoolableConnectionFactory poolConnFactory = null;

		try {
			connFactory = new DriverManagerConnectionFactory(dbURL, props);
			log.debug("Connection factory initialized.");
		} catch (Exception ex) {
			log.error(
				"Connection factory couldn't be initialized, ensure database URL, username and password are correct.");
			throw new ResolutionPlugInException("Connection factory couldn't be initialized: " + ex.getMessage());
		}

		try {
			poolConnFactory =
    			new PoolableConnectionFactory(
    				connFactory,
    				objectPool,
    				new StackKeyedObjectPoolFactory(),
    				null,
    				false,
					true);
		} catch (Exception ex) {
			log.debug("Poolable connection factory error");
		}

		dataSource = new PoolingDataSource(objectPool);
		log.info("Data Source initialized.");
		try {
			dataSource.setLogWriter(
				new Log4jPrintWriter(Logger.getLogger(JDBCDataConnector.class.getName() + ".Pool"), Priority.DEBUG));
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
			throw new ResolutionPlugInException(
				"The supplied Attribute Extractor class could not be found: " + e.getMessage());
		} catch (Exception e) {
			log.error("Unable to instantiate Attribute Extractor implementation: " + e);
			throw new ResolutionPlugInException(
				"Unable to instantiate Attribute Extractor implementation: " + e.getMessage());
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
				log.debug(
					"Implementation constructor does have a parameterized constructor, attempting to load default.");
				statementCreator = (JDBCStatementCreator) scClass.newInstance();
			}
			log.debug("Statement Creator implementation loaded.");

		} catch (ClassNotFoundException e) {
			log.error("The supplied Statement Creator class could not be found: " + e);
			throw new ResolutionPlugInException(
				"The supplied Statement Creator class could not be found: " + e.getMessage());
		} catch (Exception e) {
			log.error("Unable to instantiate Statement Creator implementation: " + e);
			throw new ResolutionPlugInException(
				"Unable to instantiate Statement Creator implementation: " + e.getMessage());
		}
	}

	public Attributes resolve(Principal principal, String requester, Dependencies depends)
		throws ResolutionPlugInException {

		log.debug("Resolving connector: (" + getId() + ")");

		//Retrieve a connection from the connection pool
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
			throw new ResolutionPlugInException("Pool didn't return a properly initialized connection.");
		}

		//Setup and execute a (pooled) prepared statement
		ResultSet rs = null;
		PreparedStatement preparedStatement;
		try {
			preparedStatement = conn.prepareStatement(searchVal);
			statementCreator.create(preparedStatement, principal, requester, depends);
			rs = preparedStatement.executeQuery();
			if (!rs.next()) {
				return new BasicAttributes();
			}

		} catch (JDBCStatementCreatorException e) {
			log.error("An ERROR occured while constructing the query");
			throw new ResolutionPlugInException("An ERROR occured while constructing the query: " + e.getMessage());
		} catch (SQLException e) {
			log.error("An ERROR occured while executing the query");
			throw new ResolutionPlugInException("An ERROR occured while executing the query: " + e.getMessage());
		}

		//Extract attributes from the ResultSet
		try {
			return extractor.extractAttributes(rs);

		} catch (JDBCAttributeExtractorException e) {
			log.error("An ERROR occured while extracting attributes from result set");
			throw new ResolutionPlugInException(
				"An ERROR occured while extracting attributes from result set: " + e.getMessage());
		} finally {
			try {
				if (preparedStatement != null) {
					preparedStatement.close();
				}
			} catch (SQLException e) {
				log.error("An error occured while closing the prepared statement: " + e);
				throw new ResolutionPlugInException("An error occured while closing the prepared statement: " + e);
			}
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
     * @see edu.internet2.middleware.shibboleth.aa.attrresolv.DataConnectorPlugIn#getFailoverDependencyId()
     */
    public String getFailoverDependencyId() {
        return failover;
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

	/**
	 * Method of extracting the attributes from the supplied result set.
	 *
	 * @param ResultSet The result set from the query which contains the attributes
	 * @return BasicAttributes as objects containing all the attributes
	 * @throws JDBCAttributeExtractorException If there is a complication in retrieving the attributes
	 */
	public BasicAttributes extractAttributes(ResultSet rs) throws JDBCAttributeExtractorException {
		BasicAttributes attributes = new BasicAttributes();

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
			if (rs.next()) {
				throw new JDBCAttributeExtractorException("Query returned more than one row.");
			}
		} catch (SQLException e) {
			log.error("An ERROR occured while retrieving result set meta data");
			throw new JDBCAttributeExtractorException(
				"An ERROR occured while retrieving result set meta data: " + e.getMessage());
		}

		return attributes;
	}
}

class DefaultStatementCreator implements JDBCStatementCreator {

	private static Logger log = Logger.getLogger(DefaultStatementCreator.class.getName());

	public void create(
		PreparedStatement preparedStatement,
		Principal principal,
		String requester,
		Dependencies depends)
		throws JDBCStatementCreatorException {

		try {
			log.debug("Creating prepared statement.  Substituting principal: (" + principal.getName() + ")");
			preparedStatement.setString(1, principal.getName());
		} catch (SQLException e) {
			log.error("Encountered an error while creating prepared statement: " + e);
			throw new JDBCStatementCreatorException(
				"Encountered an error while creating prepared statement: " + e.getMessage());
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

			if (parameter.getAttribute("attributeName") == null
				|| parameter.getAttribute("attributeName").equals("")) {
				log.error("Statement Creator Parameter must reference an attribute by name.");
				throw new JDBCStatementCreatorException("Statement Creator Parameter must reference an attribute by name.");
			}

			if (parameter.getAttribute("connectorId") != null && (!parameter.getAttribute("connectorId").equals(""))) {
				parameters.add(
					new Parameter(
						type,
						parameter.getAttribute("attributeName"),
						parameter.getAttribute("connectorId")));
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

	public void create(
		PreparedStatement preparedStatement,
		Principal principal,
		String requester,
		Dependencies depends)
		throws JDBCStatementCreatorException {

		try {
			log.debug("Creating prepared statement.  Substituting values from dependencies.");
			for (int i = 0; i < parameters.size(); i++) {
				((Parameter) parameters.get(i)).setParameterValue(preparedStatement, i + 1, depends);
			}

		} catch (Exception e) {
			log.error("Encountered an error while creating prepared statement: " + e);
			throw new JDBCStatementCreatorException(
				"Encountered an error while creating prepared statement: " + e.getMessage());
		}
	}

	protected class Parameter {
		private String type;
		private String attributeName;
		private boolean referencesConnector = false;
		private String connectorId;
		private boolean nullMissing = true;

		protected Parameter(String type, String attributeName) throws JDBCStatementCreatorException {
			if ((!type.equalsIgnoreCase("String"))
				&& (!type.equalsIgnoreCase("Integer"))
				&& (!type.equalsIgnoreCase("Byte"))
				&& (!type.equalsIgnoreCase("Double"))
				&& (!type.equalsIgnoreCase("Float"))
				&& (!type.equalsIgnoreCase("Long"))
				&& (!type.equalsIgnoreCase("Short"))
				&& (!type.equalsIgnoreCase("Boolean"))
				&& (!type.equalsIgnoreCase("Date"))
				&& (!type.equalsIgnoreCase("Blob"))
				&& (!type.equalsIgnoreCase("Clob"))) {
				log.error("Unsupported type configured for Statement Creator Parameter.");
				throw new JDBCStatementCreatorException("Unsupported type on Statement Creator Parameter.");
			}
			this.type = type;
			this.attributeName = attributeName;
		}

		protected Parameter(String type, String attributeName, String connectorId)
			throws JDBCStatementCreatorException {
			this(type, attributeName);
			referencesConnector = true;
			this.connectorId = connectorId;

		}

		protected void setParameterValue(PreparedStatement preparedStatement, int valueIndex, Dependencies depends)
			throws JDBCStatementCreatorException {

			//handle values from DataConnectors
			if (referencesConnector) {
				Attributes attributes = depends.getConnectorResolution(connectorId);
				if (attributes == null) {
					log.error(
						"Statement Creator misconfiguration: Connector ("
							+ connectorId
							+ ") is not a dependency of this JDBCDataConnector.");
					throw new JDBCStatementCreatorException(
						"Statement Creator misconfiguration: Connector ("
							+ connectorId
							+ ") is not a dependency of this JDBCDataConnector.");
				}

				Attribute attribute = attributes.get(attributeName);
				if (attribute == null || attribute.size() < 1) {
					if (nullMissing) {
						try {
							preparedStatement.setNull(valueIndex, Types.NULL);
							return;
						} catch (SQLException e) {
							log.error(
								"Encountered a problem while attempting to convert missing attribute value to null parameter.");
						}
					}
					log.error("Cannot parameterize prepared statement: missing dependency value.");
					throw new JDBCStatementCreatorException("Cannot parameterize prepared statement: missing dependency value.");
				}

				if (attribute.size() > 1) {
					log.error("Statement Creator encountered a multivalued dependent attribute.");
					throw new JDBCStatementCreatorException("Statement Creator encountered a multivalued dependent attribute.");
				}

				try {
					setSpecificParameter(preparedStatement, valueIndex, attribute.get());
					return;
				} catch (NamingException e) {
					log.error(
						"Statement Creator encountered an error while extracting attributes from a Data Conector: "
							+ e);
					throw new JDBCStatementCreatorException(
						"Statement Creator encountered an error while extracting attributes from a Data Conector: "
							+ e.getMessage());
				}
			}

			//handle values from AttributeDefinitons
			ResolverAttribute attribute = depends.getAttributeResolution(attributeName);
			if (attribute != null) {
				Iterator iterator = attribute.getValues();
				if (iterator.hasNext()) {
					setSpecificParameter(preparedStatement, valueIndex, iterator.next());
					if (iterator.hasNext()) {
						log.error("Statement Creator encountered a multivalued dependent attribute.");
						throw new JDBCStatementCreatorException("Statement Creator encountered a multivalued dependent attribute.");
					}
					return;
				}
			}
			if (nullMissing) {
				try {
					preparedStatement.setNull(valueIndex, Types.NULL);
					return;
				} catch (SQLException e) {
					log.error(
						"Encountered a problem while attempting to convert missing attribute value to null parameter.");
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
					preparedStatement.setNull(valueIndex, Types.NULL);
					return;
				} catch (SQLException e) {
					log.error(
						"Encountered a problem while attempting to convert missing attribute value to null parameter.");
					throw new JDBCStatementCreatorException("Encountered a problem while attempting to convert missing attribute value to null parameter.");
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
					//If you want to be frustrated by the java class library, look no further...
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
					preparedStatement.setDate(
						valueIndex,
						new java.sql.Date(new SimpleDateFormat().parse((String) object).getTime()));
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
