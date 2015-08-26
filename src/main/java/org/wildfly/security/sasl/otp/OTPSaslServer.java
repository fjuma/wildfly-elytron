/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.sasl.otp;

import static java.util.Arrays.asList;
import static java.util.Collections.singletonMap;
import static java.util.Collections.unmodifiableSet;
import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.sasl.otp._private.OTPUtil.*;
import static org.wildfly.security.sasl.otp.OTP.*;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Locale;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.SaslException;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.CredentialUpdateCallback;
import org.wildfly.security.auth.callback.CredentialVerifyCallback;
import org.wildfly.security.auth.callback.TimeoutCallback;
import org.wildfly.security.auth.callback.TimeoutUpdateCallback;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.OneTimePassword;
import org.wildfly.security.password.spec.OneTimePasswordSpec;
import org.wildfly.security.sasl.util.AbstractSaslServer;
import org.wildfly.security.util.ByteStringBuilder;
import org.wildfly.security.util.CodePointIterator;

/**
 * SaslServer for the OTP SASL mechanism as defined by
 * <a href="https://tools.ietf.org/html/rfc2444">RFC 2444</a>.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
final class OTPSaslServer extends AbstractSaslServer {

    private static final int ST_CHALLENGE = 1;
    private static final int ST_PROCESS_RESPONSE = 2;

    private String previousAlgorithm;
    private String previousSeed;
    private int previousSequenceNumber;
    private byte[] previousHash;
    private NameCallback nameCallback;
    private String userName;
    private String authorizationID;
    private long time;
    private boolean locked;

    OTPSaslServer(final String mechanismName, final String protocol, final String serverName, final CallbackHandler callbackHandler) {
        super(mechanismName, protocol, serverName, callbackHandler);
    }

    public void init() {
        setNegotiationState(ST_CHALLENGE);
    }

    public String getAuthorizationID() {
        if (! isComplete()) {
            throw log.saslAuthenticationNotComplete(getMechanismName());
        }
        return authorizationID;
    }

    protected byte[] evaluateMessage(final int state, final byte[] response) throws SaslException {
        switch (state) {
            case ST_CHALLENGE: {
                final CodePointIterator cpi = CodePointIterator.ofUtf8Bytes(response);
                final CodePointIterator di = cpi.delimitedBy(0);

                authorizationID = di.hasNext() ? di.drainToString() : null;
                cpi.next(); // Skip delimiter
                userName = di.drainToString();
                validateUserName(userName);
                if ((authorizationID == null) || (authorizationID.isEmpty())) {
                    authorizationID = userName;
                }
                validateAuthorizationId(authorizationID);

                // Construct an OTP extended challenge, where:
                // OTP extended challenge = <standard OTP challenge> ext[,<extension set id>[, ...]]
                // standard OTP challenge = otp-<algorithm identifier> <sequence integer> <seed>
                nameCallback = new NameCallback("Remote authentication name", userName);
                final CredentialCallback credentialCallback = new CredentialCallback(singletonMap(OneTimePassword.class, unmodifiableSet(new LinkedHashSet<>(asList(OneTimePassword.ALGORITHM_OTP_SHA1, OneTimePassword.ALGORITHM_OTP_MD5)))));
                final TimeoutCallback timeoutCallback = new TimeoutCallback();
                handleCallbacks(nameCallback, credentialCallback, timeoutCallback);
                final OneTimePassword previousPassword = (OneTimePassword) credentialCallback.getCredential();
                if (previousPassword == null) {
                    throw log.saslUnableToRetrievePassword(getMechanismName(), userName);
                }
                previousAlgorithm = previousPassword.getAlgorithm();
                validateAlgorithm(previousAlgorithm);
                previousSeed = new String(previousPassword.getSeed(), StandardCharsets.US_ASCII);
                validateSeed(previousSeed);
                previousSequenceNumber = previousPassword.getSequenceNumber();
                validateSequenceNumber(previousSequenceNumber);
                previousHash = previousPassword.getHash();

                // Prevent a user from starting multiple simultaneous authentication sessions using the
                // timeout approach described in https://tools.ietf.org/html/rfc2289#section-9.0
                long timeout = timeoutCallback.getTimeout();
                time = Instant.now().getEpochSecond();
                if (time < timeout) {
                    // An authentication attempt is already in progress for this user
                    throw log.saslMultipleSimultaneousOTPAuthenticationsNotAllowed();
                } else {
                    updateTimeout(time + LOCK_TIMEOUT);
                    locked = true;
                }

                final ByteStringBuilder challenge = new ByteStringBuilder();
                challenge.append(previousAlgorithm);
                challenge.append(' ');
                challenge.appendNumber(previousSequenceNumber - 1);
                challenge.append(' ');
                challenge.append(previousSeed);
                challenge.append(' ');
                challenge.append(EXT);
                setNegotiationState(ST_PROCESS_RESPONSE);
                return challenge.toArray();
            }
            case ST_PROCESS_RESPONSE: {
                if (Instant.now().getEpochSecond() > (time + LOCK_TIMEOUT)) {
                    throw log.saslServerTimedOut(getMechanismName());
                }
                final CodePointIterator cpi = CodePointIterator.ofUtf8Bytes(response);
                final CodePointIterator di = cpi.delimitedBy(':');
                final String responseType = di.drainToString().toLowerCase(Locale.ENGLISH);
                skipDelims(di, cpi, ':');
                final String currentOTP = responseType + ":" + di.drainToString();
                String newAlgorithm = null;
                OneTimePasswordSpec newPasswordSpec = null;
                switch (responseType) {
                    case INIT_HEX_RESPONSE:
                    case INIT_WORD_RESPONSE: {
                        try {
                            // Attempt to parse the new params and new OTP
                            skipDelims(di, cpi, ':');
                            final CodePointIterator si = di.delimitedBy(' ');
                            newAlgorithm = OTP_PREFIX + si.drainToString();
                            validateAlgorithm(newAlgorithm);
                            skipDelims(si, di, ' ');
                            int newSequenceNumber = Integer.parseInt(si.drainToString());
                            validateSequenceNumber(newSequenceNumber);
                            skipDelims(si, di, ' ');
                            String newSeed = si.drainToString();
                            validateSeed(newSeed);
                            skipDelims(di, cpi, ':');
                            final byte[] newHash;
                            if (responseType.equals(INIT_HEX_RESPONSE)) {
                                newHash = convertFromHex(di.drainToString());
                            } else {
                                newHash = convertFromWords(di.drainToString(), newAlgorithm);
                            }
                            newPasswordSpec = new OneTimePasswordSpec(newHash, newSeed.getBytes(StandardCharsets.US_ASCII), newSequenceNumber);
                        } catch (SaslException | NoSuchAlgorithmException | IllegalArgumentException e) {
                            // If the new params or new OTP could not be processed for any reason, the sequence
                            // number should be decremented if a valid current OTP is provided
                            verifyCredential(currentOTP);
                            throw log.saslOTPReinitializationFailed(e);
                        }
                        // Fall through
                    }
                    case HEX_RESPONSE:
                    case WORD_RESPONSE: {
                        if (cpi.hasNext()) {
                            throw log.saslInvalidMessageReceived(getMechanismName());
                        }
                        break;
                    }
                    default: throw log.saslInvalidOTPResponseType();
                }

                verifyCredential(currentOTP);
                if (newPasswordSpec != null) {
                    // Re-initialize the OTP sequence
                    updateCredential(newAlgorithm, newPasswordSpec);
                }

                // Check the authorization id
                if (authorizationID == null) {
                    authorizationID = userName;
                }
                final AuthorizeCallback authorizeCallback = new AuthorizeCallback(userName, authorizationID);
                handleCallbacks(authorizeCallback);
                if (! authorizeCallback.isAuthorized()) {
                    throw log.saslAuthorizationFailed(getMechanismName(), userName, authorizationID);
                }
                negotiationComplete();
                return null;
            }
            case COMPLETE_STATE: {
                  if (response != null && response.length != 0) {
                      throw log.saslMessageAfterComplete(getMechanismName());
                  }
                  return null;
            }
            default: throw Assert.impossibleSwitchCase(state);
        }
    }

    public void dispose() throws SaslException {
        previousHash = null;
        previousSeed = null;
        if (locked && (Instant.now().getEpochSecond() < (time + LOCK_TIMEOUT))) {
            updateTimeout(0);
        }
    }

    /**
     * Verify that the result of passing the user's password through the hash function once matches
     * the stored password and then update the stored password.
     *
     * @param currentOTP the current OTP, as a string
     * @throws SaslException if the password was not verified
     */
    private void verifyCredential(final String currentOTP) throws SaslException {
        final CredentialVerifyCallback credentialVerifyCallback = new CredentialVerifyCallback(currentOTP.toCharArray());
        handleCallbacks(nameCallback, credentialVerifyCallback);
        if (! credentialVerifyCallback.isVerified()) {
            throw log.saslPasswordNotVerified(getMechanismName());
        }
        updateTimeout(0);
        locked = false;
    }

    /**
     * Reset the user's password.
     *
     * @param newAlgorithm the new algorithm
     * @param newPasswordSpec the new password spec
     * @throws SaslException if the stored password was not updated
     */
    private void updateCredential(final String newAlgorithm, final OneTimePasswordSpec newPasswordSpec) throws SaslException {
        try {
            final PasswordFactory passwordFactory = PasswordFactory.getInstance(newAlgorithm);
            final OneTimePassword newPassword = (OneTimePassword) passwordFactory.generatePassword(newPasswordSpec);
            final CredentialUpdateCallback credentialUpdateCallback = new CredentialUpdateCallback(newPassword);
            handleCallbacks(nameCallback, credentialUpdateCallback);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw log.saslUnableToUpdatePassword(getMechanismName(), userName);
        }
    }

    private void updateTimeout(final long newTimeout) throws SaslException {
        final TimeoutUpdateCallback timeoutUpdateCallback = new TimeoutUpdateCallback(newTimeout);
        handleCallbacks(nameCallback, timeoutUpdateCallback);
    }
}
