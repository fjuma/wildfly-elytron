/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.http.oidc;

import static org.jboss.logging.Logger.Level.ERROR;
import static org.jboss.logging.Logger.Level.WARN;
import static org.jboss.logging.annotations.Message.NONE;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.ValidIdRange;
import org.jboss.logging.annotations.ValidIdRanges;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
@ValidIdRanges({
        @ValidIdRange(min = 19000, max = 19999)
})
interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.http.oidc");

    @Message(id = 19000, value = "Unexpected HTTP status code in response from OIDC provider \"%d\"")
    OidcException unexpectedResponseCodeFromOidcProvider(int responseCode);

    @Message(id = 19001, value = "No entity in response from OIDC provider")
    OidcException noEntityInResponse();

    @Message(id = 19002, value = "Unexpected error sending request to OIDC provider")
    OidcException unexpectedErrorSendingRequestToOidcProvider(@Cause Exception cause);

    @Message(id = 19003, value = "Either issuer-url or auth-server-url needs to be configured")
    IllegalArgumentException issuerUrlOrAuthServerUrlNeedsToBeConfigured();

    @LogMessage
    @Message(id = 19004, value = "Loaded OpenID provider metadata from '%s'")
    void loadedOpenIdProviderMetadata(String discoveryUrl);

    @LogMessage(level = WARN)
    @Message(id = 19005, value = "Unable to load OpenID provider metadata from %s")
    void unableToLoadOpenIdProviderMetadata(String discoveryUrl);

    @Message(id = 19006, value = "Failed to decode request URI")
    RuntimeException failedToDecodeRequestUri(@Cause Exception cause);

    @Message(id = 19007, value = "Failed to write to response output stream")
    RuntimeException failedToWriteToResponseOutputStream(@Cause Exception cause);

    @Message(id = 19008, value = "Unable to parse token")
    IllegalArgumentException unableToParseToken();

    @Message(id = 19009, value = "OIDC client configuration file not found")
    RuntimeException oidcConfigFileNotFound(@Cause Exception cause);

    @LogMessage(level = ERROR)
    @Message(id = 19010, value = "Failed to invoke remote logout")
    void failedToInvokeRemoteLogout(@Cause Throwable cause);

    @LogMessage(level = ERROR)
    @Message(id = 19011, value = "Refresh token failure")
    void refreshTokenFailure(@Cause Throwable cause);

    @LogMessage(level = ERROR)
    @Message(id = 19012, value = "Refresh token failure status: %d %s")
    void refreshTokenFailureStatus(int status, String error);

    @LogMessage(level = ERROR)
    @Message(id = 19013, value = "Failed verification of token: %s")
    void failedVerificationOfToken(String error);

    @LogMessage(level = ERROR)
    @Message(id = 19014, value = "Failed to refresh the token with a longer time-to-live than the minimum")
    void failedToRefreshTokenWithALongerTTLThanMin();

    @Message(id = 19015, value = "No expected issuer given")
    IllegalArgumentException noExpectedIssuerGiven();

    @Message(id = 19016, value = "No client ID given")
    IllegalArgumentException noClientIDGiven();

    @Message(id = 19017, value = "No expected JWS algorithm given")
    IllegalArgumentException noExpectedJwsAlgorithmGiven();

    @Message(id = 19018, value = "No JWKS public key or client secret key given")
    IllegalArgumentException noJwksPublicKeyOrClientSecretKeyGiven();

    @Message(id = 19019, value = "Invalid ID token")
    OidcException invalidIDToken(@Cause Throwable cause);

    @Message(id = NONE, value = "Unexpected value for azp (issued for) claim")
    String unexpectedValueForIssuedForClaim();

    @Message(id = 19020, value = "Invalid token claim value")
    IllegalArgumentException invalidTokenClaimValue();

    @Message(id = 19021, value = "Invalid ID token claims")
    OidcException invalidIDTokenClaims();

    @Message(id = 19022, value = "Must set 'realm' in config")
    RuntimeException keycloakRealmMissing();

    @Message(id = 19023, value = "Must set 'resource' in config")
    RuntimeException resourceMissing();

    @Message(id = 19024, value = "For bearer auth, you must set the 'realm-public-key' or one of 'auth-server-url' and 'issuer-url'")
    IllegalArgumentException invalidConfigurationForBearerAuth();

    @Message(id = 19025, value = "Must set 'auth-server-url' or 'issuer-url'")
    RuntimeException authServerUrlOrIssuerUrlMustBeSet();

    @LogMessage(level = WARN)
    @Message(id = 19026, value = "Client '%s' does not have a secret configured")
    void noClientSecretConfigured(String clientId);

    @Message(id = 19027, value = "Unsupported public key")
    IllegalArgumentException unsupportedPublicKey();

    @Message(id = 19028, value = "Unable to create signed token")
    IllegalArgumentException unableToCreateSignedToken();

    @Message(id = 19029, value = "Configuration of jwt credentials is missing or incorrect for client '%s'")
    RuntimeException invalidJwtClientCredentialsConfig(String clientId);

    @Message(id = 19030, value = "Missing parameter '%s' in jwt credentials for client %s")
    RuntimeException missingParameterInJwtClientCredentialsConfig(String parameter, String clientId);

    @Message(id = 19031, value = "Unable to parse key '%s' with value '%s'")
    IllegalArgumentException unableToParseKeyWithValue(String key, Object value);

    @Message(id = 19032, value = "Unable to load key with alias '%s' from keystore")
    RuntimeException unableToLoadKeyWithAlias(String alias);

    @Message(id = 19033, value = "Unable to load private key from keystore")
    RuntimeException unableToLoadPrivateKey(@Cause Throwable cause);

    @Message(id = 19034, value = "Unable to find keystore file '%s'")
    RuntimeException unableToFindKeystoreFile(String keystoreFile);

    @Message(id = 19035, value = "Configuration of secret jwt client credentials is missing or incorrect for client '%s'")
    RuntimeException invalidJwtClientCredentialsUsingSecretConfig(String clientId);

    @Message(id = 19036, value = "Invalid value for 'algorithm' in secret jwt client credentials configuration for client '%s'")
    RuntimeException invalidAlgorithmInJwtClientCredentialsConfig(String clientId);

    @Message(id = 19037, value = "Unable to determine client credentials provider type for client '%s'")
    RuntimeException unableToDetermineClientCredentialsProviderType(String clientId);

    @Message(id = 19038, value = "Unable to find client credentials provider '%s'")
    RuntimeException unableToFindClientCredentialsProvider(String provider);

    @Message(id = 19039, value = "Unable to load keystore")
    RuntimeException unableToLoadKeyStore(@Cause Throwable cause);

    @Message(id = 19040, value = "Unable to load truststore")
    RuntimeException unableToLoadTrustStore(@Cause Throwable cause);

    @Message(id = 19041, value = "Unable to find truststore file '%s'")
    RuntimeException unableToFindTrustStoreFile(String trustStoreFile);

    @Message(id = 19042, value = "Unexpected value for at_hash claim")
    String unexpectedValueForAtHashClaim();

    @Message(id = 19043, value = "Uknown algorithm: '%s'")
    IllegalArgumentException unknownAlgorithm(String algorithm);

    @LogMessage(level = WARN)
    @Message(id = 19044, value = "Failed to parse token from cookie")
    void failedToParseTokenFromCookie(@Cause Throwable cause);

    @Message(id = 19045, value = "Unable to create redirect response")
    IllegalArgumentException unableToCreateRedirectResponse(@Cause Throwable cause);

    @Message(id = 19046, value = "Unable to set auth server URL")
    RuntimeException unableToSetAuthServerUrl(@Cause Throwable cause);

    @Message(id = 19047, value = "Unable resolve a relative URL")
    RuntimeException unableToResolveARelativeUrl();

    @Message(id = 19048, value = "Invalid URI: '%s'")
    RuntimeException invalidUri(String uri);



}

