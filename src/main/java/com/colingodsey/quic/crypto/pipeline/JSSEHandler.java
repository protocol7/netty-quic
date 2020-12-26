package com.colingodsey.quic.crypto.pipeline;

import com.colingodsey.quic.QUIC;
import com.colingodsey.quic.crypto.TLS;
import com.colingodsey.quic.crypto.context.CryptoContext;
import com.colingodsey.quic.packet.Packet;
import com.colingodsey.quic.packet.frame.Crypto;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import org.openjsse.javax.net.ssl.ExtendedSSLSession;
import org.openjsse.javax.net.ssl.SSLParameters;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class JSSEHandler extends SimpleChannelInboundHandler<Crypto> {
    static final ExecutorService defaultBlockingExecutor = new ThreadPoolExecutor(
            0, 128,
            60L, TimeUnit.SECONDS,
            new SynchronousQueue<>());
    static final ByteBuffer EMPTY_BYTEBUFFER = ByteBuffer.wrap(new byte[0]);

    final ExecutorService blockingExecutor;
    final boolean isServer;
    final SSLEngine engine;

    ByteBuf inBuffer, outBuffer;
    boolean dirty = false;
    boolean helloReceived = false;
    boolean helloSent = false;
    boolean awaitingInput = true;
    boolean flushedTransParams = false;

    public JSSEHandler(SSLContext context, ExecutorService backgroundExecutor) {
        isServer = true;
        engine = context.createSSLEngine();
        engine.setUseClientMode(false);
        engine.setWantClientAuth(true);

        this.blockingExecutor = backgroundExecutor == null ?
                defaultBlockingExecutor : backgroundExecutor;
    }

    public JSSEHandler(SSLContext context, String host, int port, ExecutorService backgroundExecutor) {
        isServer = false;
        engine = context.createSSLEngine(host, port);
        engine.setUseClientMode(true);
        this.blockingExecutor = backgroundExecutor == null ?
                defaultBlockingExecutor : backgroundExecutor;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        ctx.fireChannelActive();
        if (!isServer) {
            processHandshake(ctx);
            maybeFlush(ctx);
        }
    }

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        inBuffer = newHandshakeBuffer(ctx);
        outBuffer = newHandshakeBuffer(ctx);
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) {
        if (inBuffer != null) {
            inBuffer.release();
        }
        if (outBuffer != null) {
            outBuffer.release();
        }
        engine.closeOutbound();
        inBuffer = null;
        outBuffer = null;
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) {
        processHandshake(ctx);
        ctx.fireChannelReadComplete();
        maybeFlush(ctx);
    }

    protected void channelRead0(ChannelHandlerContext ctx, Crypto msg) {
        msg.writePayload(inBuffer);
    }

    protected ByteBuf newHandshakeBuffer(ChannelHandlerContext ctx) {
        return ctx.alloc().ioBuffer(engine.getSession().getPacketBufferSize());
    }

    protected void produceTLSMessage(ChannelHandlerContext ctx) {
        final ByteBuf payload = outBuffer.copy();
        outBuffer.clear();

        ctx.write(new Crypto(getEncryptionLevel(), payload));
        dirty = true;
    }

    protected Packet.Type getEncryptionLevel() {
        final boolean helloDone = (isServer && helloSent) || (!isServer && helloReceived);
        return helloDone ? Packet.Type.HANDSHAKE : Packet.Type.INITIAL;
    }

    protected void processHandshakeIteration(ChannelHandlerContext ctx) {
        try {
            final SSLEngineResult readRes = engine.unwrap(inBuffer.nioBuffer(), EMPTY_BYTEBUFFER);
            final SSLEngineResult writeRes = engine.wrap(EMPTY_BYTEBUFFER,
                    outBuffer.nioBuffer(outBuffer.writerIndex(), outBuffer.writableBytes()));

            awaitingInput = readRes.getStatus() == Status.BUFFER_UNDERFLOW;

            if (inBuffer.isReadable() && !awaitingInput) {
                helloReceived = true;
            }

            outBuffer.writerIndex(outBuffer.writerIndex() + writeRes.bytesProduced());
            inBuffer.skipBytes(readRes.bytesConsumed());

            if (!inBuffer.isReadable()) {
                inBuffer.clear();
            }

            if (outBuffer.isReadable()) {
                produceTLSMessage(ctx);
                helloSent = true;
            }

            checkKeys(ctx);
        } catch (SSLException e) {
            ctx.fireExceptionCaught(e);
        }
    }

    protected void checkKeys(ChannelHandlerContext ctx) {
        final QUIC.Config config = QUIC.config(ctx);

        SSLSession session = engine.getHandshakeSession();
        if (session == null) {
            session = engine.getSession();
        }

        final ByteBuffer transParams = ((ExtendedSSLSession) session).getQUICTransParams();
        TLS.TransportParams.consumeTransportParams(transParams, QUIC.config(ctx).getRemoteTransport());

        try {
            if (engine instanceof org.openjsse.javax.net.ssl.SSLEngine && session != null) {
                final org.openjsse.javax.net.ssl.SSLEngine openEngine = (org.openjsse.javax.net.ssl.SSLEngine) engine;

                if (config.getHandshakeContext() == null && openEngine.getHandshakeReadSecret() != null) {
                    config.setHandshakeContext(
                            CryptoContext.createKeyed(session.getCipherSuite(),
                                    openEngine.getHandshakeWriteSecret(), openEngine.getHandshakeReadSecret()));
                    onHandshakeKey(ctx);
                }

                if (config.getMasterContext() == null && openEngine.getMasterReadSecret() != null) {
                    config.setMasterContext(
                            CryptoContext.createKeyed(session.getCipherSuite(),
                                    openEngine.getMasterWriteSecret(), openEngine.getMasterReadSecret()));
                    onMasterKey(ctx);
                }
            }
        } catch (GeneralSecurityException e) {
            ctx.fireExceptionCaught(e);
        }
    }

    protected void onHandshakeKey(ChannelHandlerContext ctx) {
        // NOOP
    }

    protected void onMasterKey(ChannelHandlerContext ctx) {
        // NOOP
    }

    protected boolean shouldWrap() {
        return engine.getHandshakeStatus() == HandshakeStatus.NEED_WRAP;
    }

    protected boolean shouldUnwrap() {
        return engine.getHandshakeStatus() == HandshakeStatus.NEED_UNWRAP && inBuffer.isReadable() && !awaitingInput;
    }

    protected void maybeFlush(ChannelHandlerContext ctx) {
        if (dirty) {
            dirty = false;
            ctx.flush();
        }
    }

    protected void processHandshake(ChannelHandlerContext ctx) {
        if (!flushedTransParams) {
            final SSLParameters sParams = (SSLParameters) engine.getSSLParameters();
            sParams.setQUICTransParams(TLS.TransportParams.produceTransportParams(
                    QUIC.config(ctx).getLocalTransport()));
            engine.setSSLParameters(sParams);
            flushedTransParams = true;
        }
        processHandshakeIteration(ctx);

        while (shouldWrap() || shouldUnwrap()) {
            processHandshakeIteration(ctx);
        }

        if (engine.getHandshakeStatus() == HandshakeStatus.NEED_TASK) {
            final List<Runnable> taskList = new ArrayList<>();
            Runnable runnable;
            while ((runnable = engine.getDelegatedTask()) != null) {
                taskList.add(runnable);
            }
            assert !taskList.isEmpty() : "NEED_TASK lies";
            taskList.add(() -> ctx.channel().eventLoop().execute(() -> {
                processHandshake(ctx);
                checkKeys(ctx);
                maybeFlush(ctx);
            }));
            blockingExecutor.execute(() -> taskList.forEach(Runnable::run));
        }
    }
}
