package com.colingodsey.quic.crypto;

import com.colingodsey.quic.utils.TestSSLContext;
import org.junit.Test;
import org.openjsse.javax.net.ssl.ExtendedSSLSession;
import org.openjsse.javax.net.ssl.SSLParameters;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLSession;
import java.nio.ByteBuffer;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TLSTest {
    @Test
    public void jvmTest() {
        SSLEngine engine = TestSSLContext.sslContext.createSSLEngine();
        System.out.println(Arrays.asList(engine.getEnabledCipherSuites()));
        System.out.println(Arrays.asList(engine.getEnabledProtocols()));

        //TSL 1.3 is java 11 only
        assertTrue("This JVM does not support TLSv1.3",
                Arrays.asList(engine.getEnabledCipherSuites()).contains("TLS_AES_128_GCM_SHA256"));
    }

    /*void setQuicParam(SSLEngine engine, TransportParams.Type type, long value) {
        SSLParameters params = (SSLParameters) engine.getSSLParameters();
        //params.setQUICTransParams(type, value);
        engine.setSSLParameters(params);
    }*/

    @Test
    public void rawHandshake() throws Exception {
        SSLEngine client = TestSSLContext.sslContext.createSSLEngine("dummy.example.com", 80);
        SSLEngine server = TestSSLContext.sslContext.createSSLEngine();
        ByteBuffer clientTPBytes = ByteBuffer.wrap(new byte[] {1, 1});
        ByteBuffer serverTPBytes = ByteBuffer.wrap(new byte[] {1, 2});

        client.setUseClientMode(true);
        server.setUseClientMode(false);
        server.setWantClientAuth(true);

        SSLParameters sParams = (SSLParameters) server.getSSLParameters();
        sParams.setQUICTransParams(serverTPBytes);
        server.setSSLParameters(sParams);

        SSLParameters cParams = (SSLParameters) client.getSSLParameters();
        cParams.setQUICTransParams(clientTPBytes);
        client.setSSLParameters(cParams);

        boolean dataDone = false;
        int itrs = 200;

        final SSLSession clientSession = client.getSession();
        final int appBufferMax = clientSession.getApplicationBufferSize();
        final int netBufferMax = clientSession.getPacketBufferSize();

        final ByteBuffer clientOut = ByteBuffer.wrap("Hi Server, I'm Client".getBytes());
        final ByteBuffer clientIn = ByteBuffer.allocateDirect(appBufferMax + 64);
        final ByteBuffer cToS = ByteBuffer.allocateDirect(netBufferMax);
        final ByteBuffer serverOut = ByteBuffer.wrap("Hello Client, I'm Server".getBytes());
        final ByteBuffer serverIn = ByteBuffer.allocateDirect(appBufferMax + 64);
        final ByteBuffer sToC = ByteBuffer.allocateDirect(netBufferMax);

        while (!isEngineClosed(client) || !isEngineClosed(server)) {
            if (itrs-- < 0) {
                throw new RuntimeException("Too many iterations. Server outbound done: "
                        + server.isOutboundDone() + ", inbound done: " + server.isInboundDone());
            }

            System.out.println("===========");
            int clientOutBytes = clientOut.remaining();
            int serverOutBytes = serverOut.remaining();
            checkStatus(client.wrap(clientOut, cToS), client);
            checkStatus(server.wrap(serverOut, sToC), server);

            if (clientOutBytes != clientOut.remaining()) {
                System.out.println("Wrote client data bytes: " + (clientOutBytes - clientOut.remaining()));
            }
            if (serverOutBytes != serverOut.remaining()) {
                System.out.println("Wrote server data bytes: " + (serverOutBytes - serverOut.remaining()));
            }

            cToS.flip();
            sToC.flip();

            System.out.println("-----");

            checkStatus(client.unwrap(sToC, clientIn), client);
            checkStatus(server.unwrap(cToS, serverIn), server);

            cToS.compact();
            sToC.compact();

            if (!dataDone && (clientOut.limit() == serverIn.position()) &&
                    (serverOut.limit() == clientIn.position())) {
                checkTransfer(serverOut, clientIn);
                checkTransfer(clientOut, serverIn);

                System.out.println("\tClosing clientEngine's *OUTBOUND*...");
                client.closeOutbound();
                dataDone = true;
            }

            if (server.isInboundDone() && !server.isOutboundDone()) {
                System.out.println("\tClosing serverEngine's *OUTBOUND*...");
                server.closeOutbound();
            }
        }

        assertTrue(client.isOutboundDone());
        assertTrue(server.isInboundDone());
        assertEquals("TLS_AES_256_GCM_SHA384", client.getSession().getCipherSuite());
        assertEquals("TLS_AES_256_GCM_SHA384", server.getSession().getCipherSuite());

        assertEquals(clientTPBytes, ((ExtendedSSLSession) server.getSession()).getQUICTransParams());
        assertEquals(serverTPBytes, ((ExtendedSSLSession) client.getSession()).getQUICTransParams());
    }

    private static void checkTransfer(ByteBuffer a, ByteBuffer b)
            throws Exception {
        a.flip();
        b.flip();

        if (!a.equals(b)) {
            throw new Exception("Data didn't transfer cleanly");
        } else {
            System.out.println("\tData transferred cleanly");
        }

        a.position(a.limit());
        b.position(b.limit());
        a.limit(a.capacity());
        b.limit(b.capacity());
    }

    private static void runDelegatedTasks(SSLEngineResult result, SSLEngine engine) throws Exception {
        if (result.getHandshakeStatus() == HandshakeStatus.NEED_TASK) {
            Runnable runnable;
            while ((runnable = engine.getDelegatedTask()) != null) {
                System.out.println("\trunning delegated task, client: " + engine.getUseClientMode());
                runnable.run();
            }
            HandshakeStatus hsStatus = engine.getHandshakeStatus();
            if (hsStatus == HandshakeStatus.NEED_TASK) {
                throw new Exception("handshake shouldn't need additional tasks");
            }
            assertTrue(hsStatus == HandshakeStatus.NEED_WRAP);
        }
    }

    private static boolean isEngineClosed(SSLEngine engine) {
        return engine.isOutboundDone() && engine.isInboundDone();
    }

    private static void checkStatus(SSLEngineResult res, SSLEngine engine) throws Exception {
        runDelegatedTasks(res, engine);
    }
}
