package com.colingodsey.quic.pipeline.component;

import io.netty.util.ReferenceCountUtil;

import java.util.SortedSet;
import java.util.TreeSet;
import java.util.function.Consumer;

import com.colingodsey.quic.packet.frame.Frame;

public class FrameOrdering<T extends Frame.Orderable> {
    protected SortedSet<T> queue = new TreeSet<>(Frame.Orderable.Comparator.INSTANCE);
    protected long offset = 0;

    public void process(T msg, Consumer<T> out) {
        assert msg.getOffset() >= 0;
        if (msg.getOffset() == offset) {
            ReferenceCountUtil.retain(msg);
            do {
                out.accept(msg);
                queue.remove(msg);
                offset += msg.getPayloadLength();
            } while (!queue.isEmpty() && (msg = queue.first()).getOffset() == offset);
        } else if (msg.getOffset() > offset && !queue.contains(msg)) {
            queue.add(ReferenceCountUtil.retain(msg));
        }
    }

    public int size() {
        int size = 0;
        for (T item : queue) {
            size += item.getPayloadLength();
        }
        return size;
    }

    public void clear() {
        queue.forEach(ReferenceCountUtil::safeRelease);
        queue.clear();
    }
}
