/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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

import static org.wildfly.security.http.oidc.ElytronMessages.log;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.EnumSet;
import java.util.UUID;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpRequestBase;
import org.wildfly.security.json.util.JsonSerialization;

/**
 * Constants and utility methods related to the OpenID Connect HTTP mechanism.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class Oidc {

    public static final String JSON_CONTENT_TYPE = "application/json";
    public static final String HTML_CONTEXT_TYPE = "text/html";
    public static final String DISCOVERY_PATH = ".well-known/openid-configuration";
    public static final String KEYCLOAK_REALMS_PATH = "realms/";
    public static final String CLIENTS_MANAGEMENT_REGISTER_NODE_PATH = "clients-managements/register-node";
    public static final String CLIENTS_MANAGEMENT_UNREGISTER_NODE_PATH = "clients-managements/unregister-node";
    public static final String SLASH = "/";
    public static final String OIDC_CLIENT_CONTEXT_KEY = OidcClientContext.class.getName();
    public static final String CLIENT_ID = "client_id";
    public static final String CODE = "code";
    public static final String ERROR = "error";
    public static final String LOGIN_HINT = "login_hint";
    public static final String MAX_AGE = "max_age";
    public static final String PROMPT = "prompt";
    public static final String SCOPE = "scope";
    public static final String UI_LOCALES = "ui_locales";
    public static final String OIDC_SCOPE = "openid";
    public static final String REDIRECT_URI = "redirect_uri";
    public static final String RESPONSE_TYPE = "response_type";
    public static final String STATE = "state";
    public static final int INVALID_ISSUED_FOR_CLAIM = -1;
    static final String OIDC_CLIENT_CONFIG_RESOLVER = "oidc.config.resolver";
    static final String OIDC_CONFIG_FILE_LOCATION = "oidc.config.file";
    static final String OIDC_JSON_FILE = "/WEB-INF/oidc.json";
    static final String JSON_CONFIG_CONTEXT_PARAM = "org.wildfly.security.http.oidc.json.config";
    static final String AUTHORIZATION = "authorization";

    // keycloak-specific request parameter used to specify the identifier of the identity provider that should be used to authenticate a user
    public static final String KC_IDP_HINT = "kc_idp_hint";



   static <T> T sendJsonHttpRequest(OidcClientConfiguration oidcClientConfiguration, HttpRequestBase httpRequest, Class<T> clazz) throws OidcException {
        try {
            HttpResponse response = oidcClientConfiguration.getClient().execute(httpRequest);
            int status = response.getStatusLine().getStatusCode();
            if (status != 200) {
                close(response);
                log.unexpectedResponseCodeFromOidcProvider(status);
            }
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                log.noEntityInResponse();
            }
            InputStream is = entity.getContent();
            try {
                return JsonSerialization.readValue(is, clazz);
            } finally {
                try {
                    is.close();
                } catch (IOException ignored) {

                }
            }
        } catch (IOException e) {
            throw log.unexpectedErrorSendingRequestToOidcProvider(e);
        }
    }

    private static void close(HttpResponse response) {
        if (response.getEntity() != null) {
            try {
                response.getEntity().getContent().close();
            } catch (IOException e) {

            }
        }
    }

    public enum SSLRequired {

        ALL,
        EXTERNAL,
        NONE;

        public boolean isRequired(String address) {
            switch (this) {
                case ALL:
                    return true;
                case NONE:
                    return false;
                case EXTERNAL:
                    return !isLocal(address);
                default:
                    return true;
            }
        }

        private boolean isLocal(String remoteAddress) {
            try {
                InetAddress inetAddress = InetAddress.getByName(remoteAddress);
                return inetAddress.isAnyLocalAddress() || inetAddress.isLoopbackAddress() || inetAddress.isSiteLocalAddress();
            } catch (UnknownHostException e) {
                return false;
            }
        }
    }

    public enum TokenStore {
        SESSION,
        COOKIE
    }

    public enum ClientCredentialsProviderType {
        SECRET("secret"),
        JWT("jwt"),
        SECRET_JWT("secret-jwt")
        ;

        private final String value;

        private ClientCredentialsProviderType(final String value) {
            this.value = value;
        }

        /**
         * Get the string value for this referral mode.
         *
         * @return the string value for this referral mode
         */
        public String getValue() {
            return value;
        }

    }

    public static String generateId() {
        return UUID.randomUUID().toString();
    }

    static int getCurrentTimeInSeconds() {
        return ((int) (System.currentTimeMillis() / 1000));
    }


}
