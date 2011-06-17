/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.idp.system.conf1;


import org.springframework.context.ApplicationContext;

import edu.internet2.middleware.shibboleth.idp.TestCaseBase;

/**
 * Base unit test case for Spring configuration tests.
 */
public abstract class BaseConf1TestCase extends TestCaseBase {
    
    /** Application context containing the loaded IdP configuration. */
    private ApplicationContext appCtx;

    /** {@inheritDoc} */
    protected void setUp() throws Exception {
        super.setUp();
        
        String[] configs = { "/data/conf1/internal.xml", "/data/conf1/service.xml", };
        appCtx = createSpringContext(configs);
    }
    
    /**
     * Gets the application context containing the IdP configuration for the unit tests.
     * 
     * @return application context containing the IdP configuration for the unit tests
     */
    protected ApplicationContext getApplicationContext(){
        return appCtx;
    }
}