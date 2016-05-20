/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.sasl.util;

import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;

/**
 * A {@link SaslClientFactory} which adds {@link AuthenticationCompleteCallback} functionality to a delegate
 * {@code SaslClientFactory}.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class AuthenticationCompleteCallbackSaslClientFactory extends AbstractDelegatingSaslClientFactory {

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate {@code SaslClientFactory}
     */
    public AuthenticationCompleteCallbackSaslClientFactory(final SaslClientFactory delegate) {
        super(delegate);
    }

    @Override
    public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        final SaslClient delegateSaslClient = delegate.createSaslClient(mechanisms, authorizationId, protocol, serverName, props, cbh);
        return delegateSaslClient == null ? null : new AbstractDelegatingSaslClient(delegateSaslClient) {
            private final AtomicBoolean complete = new AtomicBoolean();

            @Override
            public byte[] evaluateChallenge(final byte[] challenge) throws SaslException {
                try {
                    final byte[] response = delegate.evaluateChallenge(challenge);
                    if (isComplete() && complete.compareAndSet(false, true)) try {
                        cbh.handle(new Callback[] { AuthenticationCompleteCallback.SUCCEEDED });
                    } catch (Throwable ignored) {
                    }
                    return response;
                } catch (SaslException | RuntimeException | Error e) {
                    if (complete.compareAndSet(false, true)) try {
                        cbh.handle(new Callback[] { AuthenticationCompleteCallback.FAILED });
                    } catch (Throwable ignored) {
                    }
                    throw e;
                }
            }
        };
    }
}
