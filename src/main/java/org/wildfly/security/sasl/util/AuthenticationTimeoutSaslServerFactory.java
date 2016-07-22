/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import javax.security.sasl.SaslException;

import org.wildfly.common.Assert;
import org.wildfly.security.sasl.WildFlySasl;

/**
 * A {@link SaslServerFactory} which adds authentication timeout functionality to a delegate {@code SaslServerFactory}.
 * <p>
 * This {@link SaslServerFactory} must be outside of the {@link AuthenticationCompleteCallbackSaslServerFactory} in the
 * chain of SASL server factories.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class AuthenticationTimeoutSaslServerFactory extends AbstractDelegatingSaslServerFactory {

    /**
     * The default amount of time, in seconds, after which an authentication attempt should time out.
     */
    public static final long DEFAULT_TIMEOUT = 300;

    private final ScheduledExecutorService scheduledExecutorService;

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate {@code SaslServerFactory}
     * @param scheduledExecutorService the scheduled executor to use to handle authentication timeout tasks
     */
    public AuthenticationTimeoutSaslServerFactory(final SaslServerFactory delegate, final ScheduledExecutorService scheduledExecutorService) {
        super(delegate);
        Assert.checkNotNullParam("scheduledExecutorService", scheduledExecutorService);
        this.scheduledExecutorService = scheduledExecutorService;
    }

    @Override
    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        final long timeout;
        if (props.containsKey(WildFlySasl.AUTHENTICATION_TIMEOUT)) {
            timeout = Long.parseLong((String) props.get(WildFlySasl.AUTHENTICATION_TIMEOUT));
        } else {
            timeout = DEFAULT_TIMEOUT;
        }
        final NameAssignedCallbackHandler nameAssignedCallbackHandler = new NameAssignedCallbackHandler(cbh);
        final SaslServer delegateSaslServer = delegate.createSaslServer(mechanism, protocol, serverName, props, nameAssignedCallbackHandler);
        return delegateSaslServer == null ? null : new AbstractDelegatingSaslServer(delegateSaslServer) {
            private final AtomicBoolean complete = new AtomicBoolean();
            private final AtomicBoolean nameAssigned = new AtomicBoolean();
            private volatile ScheduledFuture<Void> timeoutTask;

            @Override
            public byte[] evaluateResponse(final byte[] response) throws SaslException {
                try {
                    final byte[] challenge = delegate.evaluateResponse(response);
                    if (nameAssignedCallbackHandler.isNameAssigned() && nameAssigned.compareAndSet(false, true)) {
                        // Schedule a task to terminate the authentication attempt if it takes too long
                        timeoutTask = scheduledExecutorService.schedule(() -> {
                            dispose();
                            return null;
                        }, timeout, TimeUnit.SECONDS);
                    }
                    if (isComplete() && complete.compareAndSet(false, true)) {
                        cancelTimeoutTask();
                    }
                    return challenge;
                } catch (SaslException | RuntimeException | Error e) {
                    if (isComplete() && complete.compareAndSet(false, true)) {
                        cancelTimeoutTask();
                    }
                    throw e;
                }
            }

            @Override
            public void dispose() throws SaslException {
                try {
                    super.dispose();
                } finally {
                    timeoutTask = null;
                }
            }

            private void cancelTimeoutTask() {
                if (timeoutTask != null) {
                    timeoutTask.cancel(true);
                }
            }
        };
    }

    private static class NameAssignedCallbackHandler implements CallbackHandler {

        private final CallbackHandler delegate;
        private volatile boolean nameAssigned;

        NameAssignedCallbackHandler(CallbackHandler delegate) {
            this.delegate = delegate;
        }

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                delegate.handle(new Callback[] { callback });
                if (callback instanceof NameCallback) {
                    nameAssigned = true;
                }
            }
        }

        boolean isNameAssigned() {
            return nameAssigned;
        }
    }
}
