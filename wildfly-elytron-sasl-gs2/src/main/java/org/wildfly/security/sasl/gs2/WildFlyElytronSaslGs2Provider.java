/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.sasl.gs2;

import java.security.Provider;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.WildFlyElytronBaseProvider;
import org.wildfly.security.sasl.util.SaslMechanismInformation;


/**
 * Provider for the GS2 SASL authentication mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@MetaInfServices(Provider.class)
public final class WildFlyElytronSaslGs2Provider extends WildFlyElytronBaseProvider {

    private static final long serialVersionUID = -2057804626861729995L;
    private static WildFlyElytronSaslGs2Provider INSTANCE = new WildFlyElytronSaslGs2Provider();

    /**
     * Construct a new instance.
     */
    private WildFlyElytronSaslGs2Provider() {
        super("WildFlyElytronSaslGs2Provider", "1.0", "WildFly Elytron SASL GS2 Provider");
        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.GS2_KRB5_PLUS,  "org.wildfly.security.sasl.gs2.Gs2SaslServerFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.GS2_KRB5,  "org.wildfly.security.sasl.gs2.Gs2SaslServerFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.GS2_KRB5_PLUS,  "org.wildfly.security.sasl.gs2.Gs2SaslClientFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.GS2_KRB5,  "org.wildfly.security.sasl.gs2.Gs2SaslClientFactory", emptyList, emptyMap));
    }

    /**
     * Get the GS2 SASL authentication mechanism provider instance.
     *
     * @return the GS2 SASL authentication mechanism provider instance
     */
    public static WildFlyElytronSaslGs2Provider getInstance() {
        return INSTANCE;
    }

}
