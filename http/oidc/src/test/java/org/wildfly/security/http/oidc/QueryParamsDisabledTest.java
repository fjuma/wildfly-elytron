/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.http.oidc;

import static org.junit.Assume.assumeFalse;
import static org.wildfly.security.http.oidc.KeycloakConfiguration.TENANT1_PASSWORD;
import static org.wildfly.security.http.oidc.KeycloakConfiguration.TENANT1_USER;
import static org.wildfly.security.http.oidc.Oidc.ALLOW_QUERY_PARAMS_PROPERTY_NAME;

import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests for the {@code wildfly.elytron.oidc.allow.query.params} system property.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class QueryParamsDisabledTest extends QueryParamsBaseTest {

    @BeforeClass
    public static void beforeClass() {
        assumeFalse("wildfly.elytron.oidc.allow.query.params should default to false",
                Boolean.parseBoolean(System.getProperty(ALLOW_QUERY_PARAMS_PROPERTY_NAME)));
    }

    /**
     * Test successfully logging in without query params included in the URL.
     */
    @Test
    public void testSuccessfulAuthenticationWithoutQueryParamsWithSystemPropertyEnabled() throws Exception {
        performTenantRequestWithProviderUrl(TENANT1_USER, TENANT1_PASSWORD, TENANT1_ENDPOINT, null,
                getClientUrlForTenant(TENANT1_ENDPOINT));
    }

    /**
     * Test successfully logging in with query params included in the URL.
     */
    @Test
    public void testSuccessfulAuthenticationWithQueryParamsWithSystemPropertyEnabled() throws Exception {
        // query params should not be present upon redirect
        String queryParams = "?myparam=abc";
        performTenantRequestWithProviderUrl(TENANT1_USER, TENANT1_PASSWORD, TENANT1_ENDPOINT + queryParams, null,
                getClientUrlForTenant(TENANT1_ENDPOINT));

        queryParams = "?one=abc&two=def&three=ghi";
        performTenantRequestWithProviderUrl(TENANT1_USER, TENANT1_PASSWORD, TENANT1_ENDPOINT + queryParams, null,
                getClientUrlForTenant(TENANT1_ENDPOINT));
    }

}
