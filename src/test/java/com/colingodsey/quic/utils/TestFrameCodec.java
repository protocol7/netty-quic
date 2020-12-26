package com.colingodsey.quic.utils;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageCodec;

import java.util.List;

import com.colingodsey.quic.packet.frame.Frame;

public class    TestFrameCodec extends MessageToMessageCodec<ByteBuf, Frame> {
    protected void encode(ChannelHandlerContext ctx, Frame msg, List<Object> out) throws Exception {
        final ByteBuf buf = ctx.alloc().ioBuffer();
        msg.write(buf);
        out.add(buf);
    }

    protected void decode(ChannelHandlerContext ctx, ByteBuf msg, List<Object> out) throws Exception {
        out.add(Frame.read(msg, null));
    }
}
