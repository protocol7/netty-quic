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
import java.nio.ByteBuffer;

/**
 * A standards-compliant implementation of RFC 5869
 * for HMAC-based Key Derivation Function.
 * <p>
 * HKDF follows the "extract-then-expand" paradigm, where the KDF
 * logically consists of two modules.  The first stage takes the input
 * keying material and "extracts" from it a fixed-length pseudorandom
 * key K.  The second stage "expands" the key K into several additional
 * pseudorandom keys (the output of the KDF).
 * <p>
 * HKDF was first described by Hugo Krawczyk.
 * <p>
 * This implementation is thread safe without the need for synchronization.
 * <p>
 * Simple Example:
 * <pre>
 *     byte[] pseudoRandomKey = HKDF.fromHmacSha256().extract(null, lowEntropyInput);
 *     byte[] outputKeyingMaterial = HKDF.fromHmacSha256().expand(pseudoRandomKey, null, 64);
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc5869">RFC 5869</a>
 * @see <a href="https://eprint.iacr.org/2010/264.pdf">Cryptographic Extraction and Key Derivation:
 * The HKDF Scheme</a>
 * @see <a href="https://en.wikipedia.org/wiki/HKDF">Wikipedia: HKDF</a>
 */
@SuppressWarnings("WeakerAccess")
public final class HKDF {
    /**
     * Cache instances
     */
    private static HKDF hkdfHmacSha256;
    private static HKDF hkdfHmacSha512;

    private final HkdfMacFactory macFactory;

    private HKDF(HkdfMacFactory macFactory) {
        this.macFactory = macFactory;
    }

    /**
     * Return a shared instance using HMAC with Sha256.
     * Even though shared, this instance is thread-safe.
     *
     * @return HKDF instance
     */
    public static HKDF fromHmacSha256() {
        if (hkdfHmacSha256 == null) {
            hkdfHmacSha256 = from(HkdfMacFactory.Default.hmacSha256());
        }
        return hkdfHmacSha256;
    }

    public static HKDF fromHmacSha384() {
        if (hkdfHmacSha256 == null) {
            hkdfHmacSha256 = from(HkdfMacFactory.Default.hmacSha384());
        }
        return hkdfHmacSha256;
    }

    /**
     * Return a shared instance using HMAC with Sha512.
     * Even though shared, this instance is thread-safe.
     *
     * @return HKDF instance
     */
    public static HKDF fromHmacSha512() {
        if (hkdfHmacSha512 == null) {
            hkdfHmacSha512 = from(HkdfMacFactory.Default.hmacSha512());
        }
        return hkdfHmacSha512;
    }

    /**
     * Create a new HKDF instance for given macFactory.
     *
     * @param macFactory used for HKDF
     * @return a new instance of HKDF
     */
    public static HKDF from(HkdfMacFactory macFactory) {
        return new HKDF(macFactory);
    }

    /**
     * <strong>Step 1 of RFC 5869 (Section 2.2)</strong>
     * <p>
     * The first stage takes the input keying material and "extracts" from it a fixed-length pseudorandom
     * key K. The goal of the "extract" stage is to "concentrate" and provide a more uniformly unbiased and higher entropy but smaller output.
     * This is done by utilising the diffusion properties of cryptographic MACs.
     * <p>
     * <strong>About Salts (from RFC 5869):</strong>
     * <blockquote>
     * HKDF is defined to operate with and without random salt.  This is
     * done to accommodate applications where a salt value is not available.
     * We stress, however, that the use of salt adds significantly to the
     * strength of HKDF, ensuring independence between different uses of the
     * hash function, supporting "source-independent" extraction, and
     * strengthening the analytical results that back the HKDF design.
     * </blockquote>
     *
     * @param salt                optional salt value (a non-secret random value) (can be null)
     *                             if not provided, it is set to an array of hash length of zeros.
     * @param inputKeyingMaterial data to be extracted (IKM)
     *
     * @return a new byte array pseudo random key (of hash length in bytes) (PRK) which can be used to expand
     * @see <a href="https://tools.ietf.org/html/rfc5869#section-2.2">RFC 5869 Section 2.2</a>
     */
    public byte[] extract(byte[] salt, byte[] inputKeyingMaterial) {
        return extract(macFactory.createSecretKey(salt), inputKeyingMaterial);
    }

    /**
     * Use this if you require {@link SecretKey} types by your security framework. See also
     * {@link HkdfMacFactory#createSecretKey(byte[])}.
     * <p>
     * See {@link #extract(byte[], byte[])} for description.
     *
     * @param salt                optional salt value (a non-secret random value) (can be null)
     * @param inputKeyingMaterial data to be extracted (IKM)
     * @return a new byte array pseudo random key (of hash length in bytes) (PRK) which can be used to expand
     */
    public byte[] extract(SecretKey salt, byte[] inputKeyingMaterial) {
        return new Extractor(macFactory).execute(salt, inputKeyingMaterial);
    }

    /**
     * <strong>Step 2 of RFC 5869 (Section 2.3)</strong>
     * <p>
     * To "expand" the generated output of an already reasonably random input such as an existing shared key into a larger
     * cryptographically independent output, thereby producing multiple keys deterministically from that initial shared key,
     * so that the same process may produce those same secret keys safely on multiple devices, as long as the same inputs
     * are used.
     * <p>
     * <strong>About Info (from RFC 5869):</strong>
     * <blockquote>
     * While the 'info' value is optional in the definition of HKDF, it is
     * often of great importance in applications.  Its main objective is to
     * bind the derived key material to application- and context-specific
     * information.  For example, 'info' may contain a protocol number,
     * algorithm identifiers, user identities, etc.  In particular, it may
     * prevent the derivation of the same keying material for different
     * contexts (when the same input key material (IKM) is used in such
     * different contexts).
     * </blockquote>
     *
     * @param pseudoRandomKey a pseudo random key of at least hmac hash length in bytes (usually, the output from the extract step)
     * @param info            optional context and application specific information; may be null
     * @param outLengthBytes  length of output keying material in bytes
     * @return new byte array of output keying material (OKM)
     * @see <a href="https://tools.ietf.org/html/rfc5869#section-2.3">RFC 5869 Section 2.3</a>
     */
    public byte[] expand(byte[] pseudoRandomKey, byte[] info, int outLengthBytes) {
        return expand(macFactory.createSecretKey(pseudoRandomKey), info, outLengthBytes);
    }

    /**
     * Use this if you require {@link SecretKey} types by your security framework. See also
     * {@link HkdfMacFactory#createSecretKey(byte[])}.
     * <p>
     * See {@link #expand(byte[], byte[], int)} for description.
     *
     * @param pseudoRandomKey a pseudo random key of at least hmac hash length in bytes (usually, the output from the extract step)
     * @param info            optional context and application specific information; may be null
     * @param outLengthBytes  length of output keying material in bytes
     * @return new byte array of output keying material (OKM)
     */
    public byte[] expand(SecretKey pseudoRandomKey, byte[] info, int outLengthBytes) {
        return new Expander(macFactory).execute(pseudoRandomKey, info, outLengthBytes);
    }

    /**
     * Convenience method for extract &amp; expand in a single method
     *
     * @param saltExtract         optional salt value (a non-secret random value);
     * @param inputKeyingMaterial data to be extracted (IKM)
     * @param infoExpand          optional context and application specific information; may be null
     * @param outLengthByte       length of output keying material in bytes
     * @return new byte array of output keying material (OKM)
     */
    public byte[] extractAndExpand(byte[] saltExtract, byte[] inputKeyingMaterial, byte[] infoExpand, int outLengthByte) {
        return extractAndExpand(macFactory.createSecretKey(saltExtract), inputKeyingMaterial, infoExpand, outLengthByte);
    }

    /**
     * Convenience method for extract &amp; expand in a single method
     *
     * @param saltExtract         optional salt value (a non-secret random value);
     * @param inputKeyingMaterial data to be extracted (IKM)
     * @param infoExpand          optional context and application specific information; may be null
     * @param outLengthByte       length of output keying material in bytes
     * @return new byte array of output keying material (OKM)
     */
    public byte[] extractAndExpand(SecretKey saltExtract, byte[] inputKeyingMaterial, byte[] infoExpand, int outLengthByte) {
        return new Expander(macFactory).execute(macFactory.createSecretKey(
                new Extractor(macFactory).execute(saltExtract, inputKeyingMaterial)),
                infoExpand, outLengthByte);
    }

    /**
     * Get the used mac factory
     *
     * @return factory
     */
    HkdfMacFactory getMacFactory() {
        return macFactory;
    }

    /* ************************************************************************** IMPL */

    static final class Extractor {
        private final HkdfMacFactory macFactory;

        Extractor(HkdfMacFactory macFactory) {
            this.macFactory = macFactory;
        }

        /**
         * Step 1 of RFC 5869
         *
         * @param salt                optional salt value (a non-secret random value);
         *                            if not provided, it is set to an array of hash length of zeros.
         * @param inputKeyingMaterial data to be extracted (IKM)
         *
         * @return a new byte array pseudorandom key (of hash length in bytes) (PRK) which can be used to expand
         */
        byte[] execute(SecretKey salt, byte[] inputKeyingMaterial) {
            if (salt == null) {
                salt = macFactory.createSecretKey(new byte[macFactory.getMacLengthBytes()]);
            }

            if (inputKeyingMaterial == null || inputKeyingMaterial.length <= 0) {
                throw new IllegalArgumentException("provided inputKeyingMaterial must be at least of size 1 and not null");
            }

            Mac mac = macFactory.createInstance(salt);
            return mac.doFinal(inputKeyingMaterial);
        }
    }

    static final class Expander {
        private final HkdfMacFactory macFactory;

        Expander(HkdfMacFactory macFactory) {
            this.macFactory = macFactory;
        }

        /**
         * Step 2 of RFC 5869.
         *
         * @param pseudoRandomKey a pseudorandom key of at least hmac hash length in bytes (usually, the output from the extract step)
         * @param info            optional context and application specific information; may be null
         * @param outLengthBytes  length of output keying material in bytes (must be <= 255 * mac hash length)
         * @return new byte array of output keying material (OKM)
         */
        byte[] execute(SecretKey pseudoRandomKey, byte[] info, int outLengthBytes) {

            if (outLengthBytes <= 0) {
                throw new IllegalArgumentException("out length bytes must be at least 1");
            }

            if (pseudoRandomKey == null) {
                throw new IllegalArgumentException("provided pseudoRandomKey must not be null");
            }

            Mac hmacHasher = macFactory.createInstance(pseudoRandomKey);

            if (info == null) {
                info = new byte[0];
            }

            /*
            The output OKM is calculated as follows:
              N = ceil(L/HashLen)
              T = T(1) | T(2) | T(3) | ... | T(N)
              OKM = first L bytes of T
            where:
              T(0) = empty string (zero length)
              T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
              T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
              T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
              ...
             */

            byte[] blockN = new byte[0];

            int iterations = (int) Math.ceil(((double) outLengthBytes) / ((double) hmacHasher.getMacLength()));

            if (iterations > 255) {
                throw new IllegalArgumentException("out length must be maximal 255 * hash-length; requested: " + outLengthBytes + " bytes");
            }

            ByteBuffer buffer = ByteBuffer.allocate(outLengthBytes);
            int remainingBytes = outLengthBytes;
            int stepSize;

            for (int i = 0; i < iterations; i++) {
                hmacHasher.update(blockN);
                hmacHasher.update(info);
                hmacHasher.update((byte) (i + 1));

                blockN = hmacHasher.doFinal();

                stepSize = Math.min(remainingBytes, blockN.length);

                buffer.put(blockN, 0, stepSize);
                remainingBytes -= stepSize;
            }

            return buffer.array();
        }
    }
}
