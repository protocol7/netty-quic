package com.colingodsey.quic.crypto.pipeline;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import io.netty.channel.embedded.QUICTestChannel;
import io.netty.util.concurrent.ImmediateEventExecutor;

import java.util.function.Supplier;

import com.colingodsey.quic.QUIC;
import com.colingodsey.quic.packet.Packet;
import com.colingodsey.quic.packet.frame.Crypto;
import com.colingodsey.quic.utils.TestFrameCodec;
import com.colingodsey.quic.utils.TestSSLContext;

import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openjsse.javax.net.ssl.SSLEngine;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class JSSEHandlerTest {
    ImmediateEventExecutor backgroundExecutor = ImmediateEventExecutor.INSTANCE;

    Supplier<JSSEHandler> clientMakerA =
            () -> new JSSEHandler(TestSSLContext.sslContext, "localhost", 1000, backgroundExecutor);
    Supplier<JSSEHandler> clientMakerB =
            () -> new JSSEHandler(TestSSLContext.sslContext, "localhost", 1001, backgroundExecutor);
    Supplier<JSSEHandler> serverMaker =
            () -> new JSSEHandler(TestSSLContext.sslContext, backgroundExecutor);

    @Test
    public void ZtestTransParams() throws InterruptedException {
        QUICTestChannel client = new QUICTestChannel(
                cfg -> {
                    cfg.setFrameSplitSize(17);
                    cfg.getLocalTransport().setMaxData(555);
                },
                new TestFrameCodec(),
                new CryptoOrdering(),
                clientMakerA.get()
        );
        QUICTestChannel server = new QUICTestChannel(
                cfg -> cfg.getLocalTransport().setMaxData(777),
                new TestFrameCodec(),
                new CryptoOrdering(),
                serverMaker.get()
        );

        flushUntilEmpty(client, server);

        assertNotNull(QUIC.config(server).getMasterContext());
        assertNotNull(QUIC.config(client).getMasterContext());
        assertEquals(555, QUIC.config(server).getRemoteTransport().getMaxData());
        assertEquals(777, QUIC.config(client).getRemoteTransport().getMaxData());

        client.close();
        server.close();
        client.close().sync();
        server.close().sync();
        System.gc();
    }

    @Test
    public void testHandshakeLevels() throws InterruptedException {
        QUICTestChannel client = new QUICTestChannel(clientMakerB.get());
        QUICTestChannel server = new QUICTestChannel(serverMaker.get());

        testHandshake(client, server);

        client.close().sync();
        server.close().sync();
        System.gc();
    }

    @Test
    public void testCryptoOrdering() throws InterruptedException {
        QUICTestChannel client = new QUICTestChannel(
                cfg -> cfg.setFrameSplitSize(17),
                new TestFrameCodec(),
                new CryptoOrdering(),
                clientMakerA.get()
        );
        QUICTestChannel server = new QUICTestChannel(
                cfg -> cfg.setFrameSplitSize(19),
                new TestFrameCodec(),
                new CryptoOrdering(),
                serverMaker.get()
        );

        flushUntilEmpty(client, server);
        //assertEquals(555, QUIC.config(server).getRemoteTransport().getMaxData());
        //assertEquals(777, QUIC.config(client).getRemoteTransport().getMaxData());

        client.close().sync();
        server.close().sync();
        System.gc();
    }

    void checkForward(QUICTestChannel from, Packet.Type type, QUICTestChannel to) {
        from.runPendingTasks();
        to.runPendingTasks();

        Crypto msg = from.readOutbound();
        assertEquals(type, msg.getLevel());
        to.writeOneInbound(msg);
        to.flushInbound();

        from.runPendingTasks();
        to.runPendingTasks();
    }

    void forward(QUICTestChannel from, QUICTestChannel to) {
        Object msg = from.readOutbound();
        if (msg != null) {
            to.writeOneInbound(msg);
            to.flushInbound();
        }

        from.runPendingTasks();
        to.runPendingTasks();
    }

    void flushUntilEmpty(QUICTestChannel a, QUICTestChannel b) {
        while (!a.outboundMessages().isEmpty() || !b.outboundMessages().isEmpty()) {
            forward(a, b);
            forward(b, a);
        }
    }

    void testHandshake(QUICTestChannel client, QUICTestChannel server) {
        checkForward(client, Packet.Type.INITIAL, server); //CH
        checkForward(server, Packet.Type.INITIAL, client); //SH

        assertNotNull(QUIC.config(server).getHandshakeContext());
        assertNotNull(QUIC.config(client).getHandshakeContext());

        while (!server.outboundMessages().isEmpty()) {
            checkForward(server, Packet.Type.HANDSHAKE, client); //EE, CERT, CV, FIN
        }

        checkForward(client, Packet.Type.HANDSHAKE, server); //FIN
        checkForward(client, Packet.Type.HANDSHAKE, server); //NewSessionTicket

        assertNotNull(QUIC.config(server).getMasterContext());
        assertNotNull(QUIC.config(client).getMasterContext());
    }
}
