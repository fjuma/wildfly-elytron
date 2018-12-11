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

import static org.wildfly.security.util.ProviderUtil.INSTALLED_PROVIDERS;

import java.security.Provider;
import java.util.Map;
import java.util.function.Supplier;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

/**
 * The server factory for the OTP SASL mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@MetaInfServices(value = SaslServerFactory.class)
public final class OTPSaslServerFactory implements SaslServerFactory {

    private final Supplier<Provider[]> providers;

    public OTPSaslServerFactory() {
        providers = INSTALLED_PROVIDERS;
    }

    public OTPSaslServerFactory(final Provider provider) {
        providers = () -> new Provider[] { provider };
    }

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        if (SaslMechanismInformation.Names.OTP.equals(mechanism) && OTP.isMatched(props, false)) {
            final OTPSaslServer server = new OTPSaslServer(mechanism, protocol, serverName, cbh, providers);
            server.init();
            return server;
        }
        return null;
    }

    public String[] getMechanismNames(final Map<String, ?> props) {
        return OTP.isMatched(props, true) ? new String[] { SaslMechanismInformation.Names.OTP } : WildFlySasl.NO_NAMES;
    }
}
