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

import static org.apache.http.HttpHeaders.ACCEPT;
import static org.wildfly.security.http.oidc.ElytronMessages.log;
import static org.wildfly.security.http.oidc.Oidc.CLIENTS_MANAGEMENT_REGISTER_NODE_PATH;
import static org.wildfly.security.http.oidc.Oidc.CLIENTS_MANAGEMENT_UNREGISTER_NODE_PATH;
import static org.wildfly.security.http.oidc.Oidc.DISCOVERY_PATH;
import static org.wildfly.security.http.oidc.Oidc.JSON_CONTENT_TYPE;
import static org.wildfly.security.http.oidc.Oidc.KEYCLOAK_REALMS_PATH;
import static org.wildfly.security.http.oidc.Oidc.SLASH;
import static org.wildfly.security.http.oidc.Oidc.SSLRequired;
import static org.wildfly.security.http.oidc.Oidc.TokenStore;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.wildfly.security.json.util.JsonSerialization;
import org.wildfly.security.json.util.SystemPropertiesJsonParserFactory;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Builder for the OpenID Connect (OIDC) configuration for a client application. This class is based on
 * {@code org.keycloak.adapters.KeycloakDeploymentBuilder}.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author <a href="mailto:brad.culley@spartasystems.com">Brad Culley</a>
 * @author <a href="mailto:john.ament@spartasystems.com">John D. Ament</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.16.0
 */
public class OidcClientConfigurationBuilder {

    protected OidcClientConfiguration oidcClientConfiguration = new OidcClientConfiguration();

    protected OidcClientConfigurationBuilder() {
    }


    protected OidcClientConfiguration internalBuild(final AdapterConfig adapterConfig) {
        if (adapterConfig.getRealm() == null) throw new RuntimeException("Must set 'realm' in config");
        oidcClientConfiguration.setRealm(adapterConfig.getRealm());
        String resource = adapterConfig.getResource();
        if (resource == null) throw new RuntimeException("Must set 'resource' in config");
        oidcClientConfiguration.setResourceName(resource);

        String realmKeyPem = adapterConfig.getRealmKey();
        if (realmKeyPem != null) {
            PublicKey realmKey;
            try {
                realmKey = PemUtils.decodePublicKey(realmKeyPem);
                HardcodedPublicKeyLocator pkLocator = new HardcodedPublicKeyLocator(realmKey);
                oidcClientConfiguration.setPublicKeyLocator(pkLocator);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        } else {
            JWKPublicKeyLocator pkLocator = new JWKPublicKeyLocator();
            oidcClientConfiguration.setPublicKeyLocator(pkLocator);
        }

        if (adapterConfig.getSslRequired() != null) {
            oidcClientConfiguration.setSslRequired(SSLRequired.valueOf(adapterConfig.getSslRequired().toUpperCase()));
        } else {
            oidcClientConfiguration.setSslRequired(SSLRequired.EXTERNAL);
        }

        if (adapterConfig.getConfidentialPort() != -1) {
            oidcClientConfiguration.setConfidentialPort(adapterConfig.getConfidentialPort());
        }

        if (adapterConfig.getTokenStore() != null) {
            oidcClientConfiguration.setTokenStore(TokenStore.valueOf(adapterConfig.getTokenStore().toUpperCase()));
        } else {
            oidcClientConfiguration.setTokenStore(TokenStore.SESSION);
        }
        if (adapterConfig.getTokenCookiePath() != null) {
            oidcClientConfiguration.setAdapterStateCookiePath(adapterConfig.getTokenCookiePath());
        }
        if (adapterConfig.getPrincipalAttribute() != null) oidcClientConfiguration.setPrincipalAttribute(adapterConfig.getPrincipalAttribute());

        oidcClientConfiguration.setResourceCredentials(adapterConfig.getCredentials());
        oidcClientConfiguration.setClientAuthenticator(ClientCredentialsProviderUtils.bootstrapClientAuthenticator(oidcClientConfiguration));

        oidcClientConfiguration.setPublicClient(adapterConfig.isPublicClient());
        oidcClientConfiguration.setUseResourceRoleMappings(adapterConfig.isUseResourceRoleMappings());

        oidcClientConfiguration.setExposeToken(adapterConfig.isExposeToken());

        if (adapterConfig.isCors()) {
            oidcClientConfiguration.setCors(true);
            oidcClientConfiguration.setCorsMaxAge(adapterConfig.getCorsMaxAge());
            oidcClientConfiguration.setCorsAllowedHeaders(adapterConfig.getCorsAllowedHeaders());
            oidcClientConfiguration.setCorsAllowedMethods(adapterConfig.getCorsAllowedMethods());
            oidcClientConfiguration.setCorsExposedHeaders(adapterConfig.getCorsExposedHeaders());
        }

        // https://tools.ietf.org/html/rfc7636
        if (adapterConfig.isPkce()) {
            oidcClientConfiguration.setPkce(true);
        }

        oidcClientConfiguration.setBearerOnly(adapterConfig.isBearerOnly());
        oidcClientConfiguration.setAutodetectBearerOnly(adapterConfig.isAutodetectBearerOnly());
        oidcClientConfiguration.setEnableBasicAuth(adapterConfig.isEnableBasicAuth());
        oidcClientConfiguration.setAlwaysRefreshToken(adapterConfig.isAlwaysRefreshToken());
        oidcClientConfiguration.setRegisterNodeAtStartup(adapterConfig.isRegisterNodeAtStartup());
        oidcClientConfiguration.setRegisterNodePeriod(adapterConfig.getRegisterNodePeriod());
        oidcClientConfiguration.setTokenMinimumTimeToLive(adapterConfig.getTokenMinimumTimeToLive());
        oidcClientConfiguration.setMinTimeBetweenJwksRequests(adapterConfig.getMinTimeBetweenJwksRequests());
        oidcClientConfiguration.setPublicKeyCacheTtl(adapterConfig.getPublicKeyCacheTtl());
        oidcClientConfiguration.setIgnoreOAuthQueryParameter(adapterConfig.isIgnoreOAuthQueryParameter());
        oidcClientConfiguration.setRewriteRedirectRules(adapterConfig.getRedirectRewriteRules());
        oidcClientConfiguration.setVerifyTokenAudience(adapterConfig.isVerifyTokenAudience());

        if (realmKeyPem == null && adapterConfig.isBearerOnly() && adapterConfig.getAuthServerUrl() == null) {
            throw new IllegalArgumentException("For bearer auth, you must set the realm-public-key or auth-server-url");
        }
        if (adapterConfig.getAuthServerUrl() == null && (!oidcClientConfiguration.isBearerOnly() || realmKeyPem == null)) {
            throw new RuntimeException("You must specify auth-server-url");
        }
        oidcClientConfiguration.setClient(createHttpClientProducer(adapterConfig));
        oidcClientConfiguration.setAuthServerBaseUrl(adapterConfig);
        if (adapterConfig.getTurnOffChangeSessionIdOnLogin() != null) {
            oidcClientConfiguration.setTurnOffChangeSessionIdOnLogin(adapterConfig.getTurnOffChangeSessionIdOnLogin());
        }

        final PolicyEnforcerConfig policyEnforcerConfig = adapterConfig.getPolicyEnforcerConfig();

        if (policyEnforcerConfig != null) {
            oidcClientConfiguration.setPolicyEnforcer(new Callable<PolicyEnforcer>() {
                PolicyEnforcer policyEnforcer;
                @Override
                public PolicyEnforcer call() {
                    if (policyEnforcer == null) {
                        synchronized (oidcClientConfiguration) {
                            if (policyEnforcer == null) {
                                policyEnforcer = new PolicyEnforcer(oidcClientConfiguration, adapterConfig);
                            }
                        }
                    }
                    return policyEnforcer;
                }
            });
        }

        return oidcClientConfiguration;
    }

    private Callable<HttpClient> createHttpClientProducer(final AdapterConfig adapterConfig) {
        return new Callable<HttpClient>() {
            private HttpClient client;
            @Override
            public HttpClient call() {
                if (client == null) {
                    synchronized (oidcClientConfiguration) {
                        if (client == null) {
                            client = new HttpClientBuilder().build(adapterConfig);
                        }
                    }
                }
                return client;
            }
        };
    }

    public static OidcClientConfiguration build(InputStream is) {
        AdapterConfig adapterConfig = loadAdapterConfig(is);
        return new OidcClientConfigurationBuilder().internalBuild(adapterConfig);
    }

    public static AdapterConfig loadAdapterConfig(InputStream is) {
        ObjectMapper mapper = new ObjectMapper(new SystemPropertiesJsonParserFactory());
        mapper.setSerializationInclusion(JsonInclude.Include.NON_DEFAULT);
        AdapterConfig adapterConfig;
        try {
            adapterConfig = mapper.readValue(is, AdapterConfig.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return adapterConfig;
    }


    public static OidcClientConfiguration build(AdapterConfig adapterConfig) {
        return new OidcClientConfigurationBuilder().internalBuild(adapterConfig);
    }


}
