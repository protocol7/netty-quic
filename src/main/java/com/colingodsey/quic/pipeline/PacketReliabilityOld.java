package com.colingodsey.quic.pipeline;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.MessageToMessageCodec;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.GenericFutureListener;
import io.netty.util.concurrent.PromiseCombiner;

import java.util.ArrayDeque;
import java.util.List;
import java.util.Queue;

import com.colingodsey.quic.packet.Packet;
import com.colingodsey.quic.packet.frame.Ack;
import com.colingodsey.quic.packet.frame.Frame;

import com.colingodsey.quic.utils.Tuple;


/*
this has to handle everything... blah.

No point in declaring header early? This class takes frames and makes packets directly

0-RTT -> 1-RTT. same space
initial -> initial
handshake -> handshake
1-RTT -> 1-RTT

Header constructor should be made just from the type, packet number, and quic config?

THIS WOULD ALL BE EASIER IF WE HAD DETERMINISTIC LENGTHS....

Lets make packets into containers again. Calculate strict lengths, frames too.
 */
public class PacketReliabilityOld extends ChannelDuplexHandler {
    final Queue<Tuple<Frame, ChannelPromise>> frameQueue = new ArrayDeque<>();
    final Packet.Type type;

    long packetNumber = 0;

    public PacketReliabilityOld(Packet.Type type) {
        this.type = type;
    }

    //how to deal with frame length?

    /*
    Keep scratch buffer for assembling packets, if the frame makes it too large, just slice it.
    If builder makes a packet with only an ACK, also discard and slice.
     */

    //frame frameQueue
    //ack

    /*
    An endpoint MUST NOT send a packet containing only an ACK frame in response to a non-ACK-eliciting packet
    (one containing only ACK and/or PADDING frames), even if there are packet gaps which precede the received packet.
     */

    /*
    keep ticket system per packet number. promise resolution per frame.

    use ACK-ACKs to remove numbers from ack set? nooo acks are durable
     */

    //1 + last - providers good next max?

    /*
    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        if (msg instanceof Frame && ((Frame) msg).getLevel()) {
            frameQueue.add(Tuple.create((Frame) msg, promise));
        } else {
            ctx.write(msg, promise);
        }
    }

    @Override
    public void flush(ChannelHandlerContext ctx) throws Exception {
        while (shouldFlush()) {
            flushOne(ctx, 1240);
        }
        ctx.flush();
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        ctx.fireChannelRead(msg);
    }

    boolean shouldFlush() {
        return !frameQueue.isEmpty() && (frameQueue.size() > 1 || !(frameQueue.peek() instanceof Ack));
    }

    void flushOne(ChannelHandlerContext ctx, int max) {
        if (frameQueue.isEmpty()) {
            return;
        }

        assert frameQueue.size() == promiseQueue.size();

        final PacketRecord record = new PacketRecord(ctx);
        final ByteBuf buf = ctx.alloc().ioBuffer(max);
        try {
            while (buf.readableBytes() < max && shouldFlush()) {
                final Frame head = frameQueue.peek();
                final int writerIndex = buf.writerIndex();

                if (head instanceof Ack && frameQueue.size() == 1) {
                    break; //dont make any packet with only an Ack
                }

                //TODO: length hint

                head.write(buf);

                if (buf.readableBytes() > max) {
                    buf.writerIndex(writerIndex);
                    break;
                }

                frameQueue.remove();
                record.add(head, promiseQueue.remove());
            }

            if (buf.isReadable()) {
                ctx.write(new Packet(null, buf.retain())).addListener(record);
            }
        } finally {
            buf.release();
        }
    }

    class PacketRecord implements GenericFutureListener<Future<Void>> {
        final ObjectList<Frame> frames = new ObjectArrayList<>();
        final ObjectList<ChannelPromise> promises = new ObjectArrayList<>();
        final ChannelHandlerContext ctx;

        public PacketRecord(ChannelHandlerContext ctx) {
            this.ctx = ctx;
        }

        public void operationComplete(Future f) throws Exception {
            if (f.isSuccess()) {
                promises.forEach(ChannelPromise::trySuccess);
                frames.forEach(ReferenceCountUtil::release);
                frames.clear();
                promises.clear();
            } else {
                ctx.executor().execute(() -> recall(f.cause()));
            }
        }

        void recall(Throwable cause) {
            if (!(cause instanceof Ack.NackThrowable)) {
                ctx.fireExceptionCaught(cause);
            }
            while (!frames.isEmpty()) {
                consume(ctx, frames.remove(0), promises.remove(0));
            }
        }

        void add(Frame frame, ChannelPromise promise) {
            frames.add(frame);
            promises.add(promise);
        }
    }*/
}
