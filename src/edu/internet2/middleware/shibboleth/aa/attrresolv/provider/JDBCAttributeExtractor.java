/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.aa.attrresolv.provider;

import java.sql.ResultSet;

import javax.naming.directory.Attributes;

/*
 * Built at the Canada Institute for Scientific and Technical Information (CISTI
 * <ahref="http://www.cisti-icist.nrc-cnrc.gc.ca/">http://www.cisti-icist.nrc-cnrc.gc.ca/ </a>, the National Research
 * Council Canada (NRC <a href="http://www.nrc-cnrc.gc.ca/">http://www.nrc-cnrc.gc.ca/ </a>) by David Dearman, COOP
 * student from Dalhousie University, under the direction of Glen Newton, Head research (IT)
 * <ahref="mailto:glen.newton@nrc-cnrc.gc.ca">glen.newton@nrc-cnrc.gc.ca </a>.
 */

/**
 * Definition for the JDBC attribute extractor.
 * 
 * @author David Dearman (dearman@cs.dal.ca)
 * @version 1.0 July 24, 2003
 * 
 */

public interface JDBCAttributeExtractor {

	/**
	 * Method of extracting the attributes from the supplied result set.
	 * 
	 * @param rs
	 *            The result set from the query which contains the attributes
	 * @param minResultSet
	 *            The minimum number of rows that constitutes successful extraction
	 * @param maxResultSet
	 *            The maximum number of rows that constitutes successful extraction
	 * @return BasicAttributes as objects containing all the attributes
	 * @throws JDBCAttributeExtractorException
	 *             If there is a complication in retrieving the attributes
	 */
	public Attributes extractAttributes(ResultSet rs, int minResultSet, int maxResultSet)
			throws JDBCAttributeExtractorException;
}
