/*
 * Copyright 2017 Patrick Favre-Bulle
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.colingodsey.quic;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/**
 * Factory class for creating {@link Mac} hashers
 */
public interface HkdfMacFactory {

    /**
     * Creates a new instance of Hmac with given key, i.e. it must already be initialized
     * with {@link Mac#init(Key)}.
     *
     * @param key the key used, must not be null
     * @return a new mac instance
     */
    Mac createInstance(SecretKey key);

    /**
     * Get the length of the mac output in bytes
     *
     * @return the length of mac output in bytes
     */
    int getMacLengthBytes();

    /**
     * Creates a secret key from a byte raw key material to be used with {@link #createInstance(SecretKey)}
     *
     * @param rawKeyMaterial the raw key
     * @return wrapped as secret key instance or null if input is null or empty
     */
    SecretKey createSecretKey(byte[] rawKeyMaterial);

    /**
     * Default implementation
     */
    @SuppressWarnings("WeakerAccess")
    final class Default implements HkdfMacFactory {
        private final String macAlgorithmName;
        private final Provider provider;

        /**
         * Creates a factory creating HMAC with SHA-256
         *
         * @return factory
         */
        public static HkdfMacFactory hmacSha256() {
            return new Default("HmacSHA256", null);
        }

        public static HkdfMacFactory hmacSha384() {
            return new Default("HmacSHA384", null);
        }


        /**
         * Creates a factory creating HMAC with SHA-512
         *
         * @return factory
         */
        public static HkdfMacFactory hmacSha512() {
            return new Default("HmacSHA512", null);
        }

        /**
         * Creates a factory creating HMAC with SHA-1
         *
         * @return factory
         * @deprecated sha1 with HMAC should be fine, but not recommended for new protocols; see https://crypto.stackexchange.com/questions/26510/why-is-hmac-sha1-still-considered-secure
         */
        @Deprecated
        public static HkdfMacFactory hmacSha1() {
            return new Default("HmacSHA1", null);
        }

        /**
         * Creates a mac factory
         *
         * @param macAlgorithmName as used by {@link Mac#getInstance(String)}
         */
        public Default(String macAlgorithmName) {
            this(macAlgorithmName, null);
        }

        /**
         * Creates a mac factory
         *
         * @param macAlgorithmName as used by {@link Mac#getInstance(String)}
         * @param provider         the security provider, see {@link Mac#getInstance(String, Provider)}; may be null to use default
         */
        public Default(String macAlgorithmName, Provider provider) {
            this.macAlgorithmName = macAlgorithmName;
            this.provider = provider;
        }

        @Override
        public Mac createInstance(SecretKey key) {
            try {
                Mac mac = createMacInstance();
                mac.init(key);
                return mac;
            } catch (Exception e) {
                throw new IllegalStateException("could not make hmac hasher in hkdf", e);
            }
        }

        private Mac createMacInstance() {
            try {
                Mac hmacInstance;

                if (provider == null) {
                    hmacInstance = Mac.getInstance(macAlgorithmName);
                } else {
                    hmacInstance = Mac.getInstance(macAlgorithmName, provider);
                }

                return hmacInstance;
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("defined mac algorithm was not found", e);
            } catch (Exception e) {
                throw new IllegalStateException("could not create mac instance in hkdf", e);
            }
        }

        @Override
        public int getMacLengthBytes() {
            return createMacInstance().getMacLength();
        }

        @Override
        public SecretKey createSecretKey(byte[] rawKeyMaterial) {
            if (rawKeyMaterial == null || rawKeyMaterial.length <= 0) {
                return null;
            }
            return new SecretKeySpec(rawKeyMaterial, macAlgorithmName);
        }
    }
}
