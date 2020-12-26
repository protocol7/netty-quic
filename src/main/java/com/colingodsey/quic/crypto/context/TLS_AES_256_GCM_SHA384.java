package com.colingodsey.quic.crypto.context;

import com.colingodsey.quic.HKDF;
import com.colingodsey.quic.packet.component.ConnectionID;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;

public class TLS_AES_256_GCM_SHA384 extends CryptoContext {
    static final int BITS = 256;
    static final HKDF hkdf = HKDF.fromHmacSha384();

    final SecretKey wPayload;
    final IvParameterSpec wIV;
    final Cipher payloadCipher;
    final Cipher wHeaderCipher;
    final Cipher rHeaderCipher;

    final SecretKey rPayload;
    final IvParameterSpec rIV;

    TLS_AES_256_GCM_SHA384(ConnectionID connectionID, boolean isServer) throws GeneralSecurityException {
        this(new SecretKeySpec(
                hkdf.extract(QUIC_V1_INITIAL_SALT, connectionID.getBytes()), "HKDF"), isServer);
    }

    private TLS_AES_256_GCM_SHA384(SecretKey masterSecret, boolean isServer) throws GeneralSecurityException {
        this(
                expandKey(masterSecret, !isServer ? QUIC_CLIENT_IN_LABEL : QUIC_SERVER_IN_LABEL),
                expandKey(masterSecret, isServer  ? QUIC_CLIENT_IN_LABEL : QUIC_SERVER_IN_LABEL)
        );
    }

    TLS_AES_256_GCM_SHA384(SecretKey encryptKey, SecretKey decryptKey) throws GeneralSecurityException {
        payloadCipher = Cipher.getInstance("AES/GCM/NoPadding");

        wPayload = expandKey(encryptKey, QUIC_KEY_LABEL);
        wIV = expandIV(encryptKey, QUIC_IV_LABEL);
        wHeaderCipher = Cipher.getInstance("AES/ECB/NoPadding");
        wHeaderCipher.init(Cipher.ENCRYPT_MODE, expandKey(encryptKey, QUIC_HP_LABEL));

        rPayload = expandKey(decryptKey, QUIC_KEY_LABEL);
        rIV = expandIV(decryptKey, QUIC_IV_LABEL);
        rHeaderCipher = Cipher.getInstance("AES/ECB/NoPadding");
        rHeaderCipher.init(Cipher.ENCRYPT_MODE, expandKey(decryptKey, QUIC_HP_LABEL));
    }

    int getAADLength() {
        return BITS / 8;
    }

    AlgorithmParameterSpec createIV(int packetNum, boolean isEncrypt) {
        final byte[] nonce = isEncrypt ? wIV.getIV() : rIV.getIV();
        final byte[] pnBytes = BigInteger.valueOf(packetNum).toByteArray();
        final int offset = nonce.length - pnBytes.length;
        for (int i = 0 ; i < pnBytes.length ; i++) {
            nonce[offset + i] ^= pnBytes[i];
        }
        return new GCMParameterSpec(BITS, nonce);
    }

    Cipher getPayloadCipher() {
        return payloadCipher;
    }

    SecretKey getWPayloadKey() {
        return wPayload;
    }

    Cipher getWHeaderCipher() {
        return wHeaderCipher;
    }

    SecretKey getRPayloadKey() {
        return rPayload;
    }

    Cipher getRHeaderCipher() {
        return rHeaderCipher;
    }

    protected static IvParameterSpec expandIV(SecretKey key, Label label) {
        return new IvParameterSpec(hkdf.expand(key, label.bytes, label.length));
    }

    protected static SecretKey expandKey(SecretKey key, Label label) {
        return new SecretKeySpec(hkdf.expand(key, label.bytes, label.length), "AES");
    }
}
