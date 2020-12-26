package com.colingodsey.quic.crypto.context;

import static com.colingodsey.quic.utils.Utils.h2ba;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import com.colingodsey.quic.packet.Packet;
import com.colingodsey.quic.packet.component.ConnectionID;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public abstract class CryptoContext {
    static final byte[] QUIC_V1_INITIAL_SALT = h2ba("c3eef712c72ebb5a11a7d2432bb46365bef9f502");

    static final Label QUIC_CLIENT_IN_LABEL = new Label("client in", 32);
    static final Label QUIC_SERVER_IN_LABEL = new Label("server in", 32);
    static final Label QUIC_KEY_LABEL = new Label("quic key", 16);
    static final Label QUIC_IV_LABEL = new Label("quic iv", 12);
    static final Label QUIC_HP_LABEL = new Label("quic hp", 16);

    static final int SAMPLE_SIZE = 16;

    /**
     * Crypto context used for the initial phase, derived from the connection ID.
     *
     * @param connectionID ID used to derive the crypto keys.
     * @throws GeneralSecurityException
     */
    public static CryptoContext createInitial(String cipherSuite, ConnectionID connectionID, boolean isServer)
            throws GeneralSecurityException {
        switch (cipherSuite) {
            case "TLS_AES_128_GCM_SHA256":
                return new TLS_AES_128_GCM_SHA256(connectionID, isServer);
            case "TLS_AES_256_GCM_SHA384":
                return new TLS_AES_256_GCM_SHA384(connectionID, isServer);
            default:
                throw new NoSuchAlgorithmException(cipherSuite);
        }
    }

    /**
     * Crypto context used for the handshake and 1-RTT phases.
     *
     * For the handshake phase, the handshake secret from the TLS context should be used.
     * For the 1-RTT phase, the master secret from the TLS context should be used.
     *
     * @param writeKey Secret writeHeader key negotiated by TLS.
     * @param readKey Secret read key negotiated by TLS.
     * @throws GeneralSecurityException
     */
    public static CryptoContext createKeyed(String cipherSuite, SecretKey writeKey, SecretKey readKey) throws GeneralSecurityException {
        switch (cipherSuite) {
            case "TLS_AES_128_GCM_SHA256":
                return new TLS_AES_128_GCM_SHA256(writeKey, readKey);
            case "TLS_AES_256_GCM_SHA384":
                return new TLS_AES_256_GCM_SHA384(writeKey, readKey);
            default:
                throw new NoSuchAlgorithmException(cipherSuite);
        }
    }

    abstract AlgorithmParameterSpec createIV(int packetNum, boolean isEncrypt);
    abstract SecretKey getWPayloadKey();
    abstract Cipher getPayloadCipher();
    abstract Cipher getWHeaderCipher();
    abstract SecretKey getRPayloadKey();
    abstract Cipher getRHeaderCipher();
    abstract int getAADLength();

    public int payloadCrypto(ByteBuffer header, ByteBuffer payload, int packetNumber, ByteBuffer out, boolean isEncrypt) {
        final Cipher cipher = getPayloadCipher();
        try {
            cipher.init(
                    isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                    isEncrypt ? getWPayloadKey() : getRPayloadKey(),
                    createIV(packetNumber, isEncrypt)
            );
            cipher.updateAAD(header);
            return cipher.doFinal(payload, out);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] headerProtectMask(ByteBuf ePayload, int index, int pnLength, boolean isEncrypt) {
        final Cipher cipher = isEncrypt ? getWHeaderCipher() : getRHeaderCipher();
        final byte[] out = new byte[cipher.getOutputSize(SAMPLE_SIZE)];
        try {
            cipher.doFinal(
                    ePayload.nioBuffer(index + 4 - pnLength, SAMPLE_SIZE),
                    ByteBuffer.wrap(out)
            );
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return out;
    }

    public byte[] headerProtectMask(byte[] encryptedPayload, int pnLength, boolean isEncrypt) {
        return headerProtectMask(Unpooled.wrappedBuffer(encryptedPayload), 0, pnLength, isEncrypt);
    }

    protected void encrypt(Packet packet, ByteBuf out) {
        final int headerIndex = out.writerIndex();
        final int headerLength = packet.writeHeader(out).writerIndex() - headerIndex;
        final int payloadIndex = out.writerIndex();
        final int payloadLength = packet.writePayload(out).writerIndex() - payloadIndex;

        assert packet.getType().needsProtection();
        assert payloadLength == packet.getPayloadLength();

        out.ensureWritable(getAADLength()); //AAD
        final int written = payloadCrypto(
                out.nioBuffer(headerIndex, headerLength),
                out.nioBuffer(payloadIndex, payloadLength),
                packet.getPacketNumber(),
                out.nioBuffer(payloadIndex, payloadLength + getAADLength()), true);
        out.writerIndex(payloadIndex + written);

        final int pnIndex = headerIndex + headerLength - packet.getPacketNumberBytes();
        final byte[] mask = headerProtectMask(
                out, payloadIndex, packet.getPacketNumberBytes(), true);

        xor(out, headerIndex, mask[0] & packet.getType().firstByteProtectionMask());
        for (int i = 0 ; i < packet.getPacketNumberBytes() ; i++) {
            xor(out, pnIndex + i, mask[1 + i]);
        }
    }

    protected Packet decrypt(ByteBuf in) {
        final int headerIndex = in.readerIndex();
        final int preHeaderLength = Packet.getProtectedPreHeaderLength(in);
        final byte[] mask = headerProtectMask(
                in, headerIndex + preHeaderLength, 0, false);

        //unmask first byte so we can get the real packetNumberBytes
        xor(in, headerIndex, mask[0] & Packet.getType(in).firstByteProtectionMask());

        //unmask packet number
        final int pnLength = Packet.getPacketNumberBytes(in);
        final int pnIndex = headerIndex + preHeaderLength;
        for (int i = 0 ; i < pnLength ; i++) {
            xor(in, pnIndex + i, mask[1 + i]);
        }

        final int headerLength = preHeaderLength + pnLength;
        final int payloadIndex = headerIndex + headerLength;
        final int ePayloadLength = in.readableBytes() - headerLength;
        final int payloadLength = payloadCrypto(
                in.nioBuffer(headerIndex, headerLength),
                in.nioBuffer(payloadIndex, ePayloadLength),
                Packet.getPacketNumber(in, headerIndex + preHeaderLength, pnLength),
                in.nioBuffer(payloadIndex, ePayloadLength), false);

        return Packet.read(in.writerIndex(headerLength + payloadLength));
    }

    static final void xor(ByteBuf buf, int index, int value) {
        buf.setByte(index, buf.getUnsignedByte(index) ^ (value & 0xFF));
    }

    static class Label {
        static final String prefix = "tls13 ";
        static final byte[] context = new byte[] {0};

        final byte[] bytes;
        final int length;

        Label(String label, int length) {
            bytes = new byte[2 + 1 + prefix.length() + label.length() + context.length];
            this.length = length;

            final ByteBuf writer = Unpooled.wrappedBuffer(bytes).clear();
            writer.writeShort(length);
            writer.writeByte(prefix.length() + label.length());
            writer.writeCharSequence(prefix, StandardCharsets.US_ASCII);
            writer.writeCharSequence(label, StandardCharsets.US_ASCII);
            writer.writeBytes(context);
            assert writer.writableBytes() == 0;
        }
    }
}
