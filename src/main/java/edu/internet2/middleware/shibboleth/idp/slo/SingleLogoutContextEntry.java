/*
 *  Copyright 2009 NIIF Institute.
 * 
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *  under the License.
 */
package edu.internet2.middleware.shibboleth.idp.slo;

import org.joda.time.DateTime;
import org.opensaml.util.storage.AbstractExpiringObject;

/**
 *
 * @author Adam Lantos  NIIF / HUNGARNET
 */
public class SingleLogoutContextEntry extends AbstractExpiringObject {
    private static final long serialVersionUID = 8456530807574247919L;

    /** Stored single logout context. */
    private SingleLogoutContext singleLogoutContext;

    /**
     * Constructor.
     *
     * @param ctx context to store
     * @param lifetime lifetime of the entry
     */
    public SingleLogoutContextEntry(SingleLogoutContext ctx, long lifetime) {
        super(new DateTime().plus(lifetime));
        singleLogoutContext = ctx;
    }

    public SingleLogoutContext getSingleLogoutContext() {
        return singleLogoutContext;
    }
}
