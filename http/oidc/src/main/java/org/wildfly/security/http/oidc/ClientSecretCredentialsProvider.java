/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
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
import static org.wildfly.security.http.oidc.Oidc.AUTHORIZATION;
import static org.wildfly.security.http.oidc.Oidc.CLIENT_ID;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import javax.crypto.SecretKey;

import org.wildfly.common.iteration.ByteIterator;

/**
 * A client secret credentials provider.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public interface ClientSecretCredentialsProvider extends ClientCredentialsProvider {

    SecretKey getClientSecret();
}
