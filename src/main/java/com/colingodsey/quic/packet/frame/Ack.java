package com.colingodsey.quic.packet.frame;

import io.netty.buffer.ByteBuf;

import com.colingodsey.quic.utils.VariableInt;

import it.unimi.dsi.fastutil.ints.IntArrayList;
import it.unimi.dsi.fastutil.longs.LongConsumer;
import it.unimi.dsi.fastutil.longs.LongSortedSet;

import java.util.SortedSet;

public class Ack implements Frame, Frame.Initial, Frame.Handshake {
    public static final int PACKET_ID = 0x02;
    private static final int[] EMPTY_INT_ARR = new int[0];

    public final long largestAckd;
    public final long ackDelay;
    public final int ackRangeCount;
    public final int firstAck;
    final int[] gaps;
    final int[] acks;

    //TODO: ECN
    public Ack(ByteBuf in) {
        VariableInt.read(in); //id
        largestAckd = VariableInt.read(in);
        ackDelay = VariableInt.read(in);
        ackRangeCount = VariableInt.readInt(in);
        firstAck = VariableInt.readInt(in);

        gaps = new int[ackRangeCount];
        acks = new int[ackRangeCount];
        for (int i = 0 ; i < ackRangeCount ; i++) {
            gaps[i] = VariableInt.readInt(in);
            acks[i] = VariableInt.readInt(in);
        }
    }

    public Ack(long lastLargest, SortedSet<Long> ackSet, long ackDelay) {
        IntArrayList gaps = null;
        IntArrayList acks = null;

        final long largestAckd = ackSet.first();
        long cursor = largestAckd;
        int firstAck = 0;
        long rangeStart = 0;
        boolean firstPhase = true;

        for (long n : ackSet) {
            assert cursor != largestAckd || n == largestAckd : "largestAckd must be an ack!";
            assert n > lastLargest : "cant ack previously ackd value!";

            if (n > cursor) {
                throw new IllegalArgumentException("ackSet must be descending order");
            }

            if (firstPhase && n == cursor) {
                firstAck++;
                cursor--;
                continue;
            } else if (firstPhase) {
                firstPhase = false;
                gaps = new IntArrayList();
                acks = new IntArrayList();
            } else if (n == cursor) {
                cursor--;
                continue;
            } else {
                acks.add((int) (rangeStart - cursor));
            }

            assert cursor > n;

            gaps.add((int) (cursor - n));
            cursor = n - 1;
            rangeStart = n;
        }

        if (cursor > lastLargest) { //gap on tail
            if (firstPhase) {
                firstPhase = false;
                gaps = new IntArrayList();
                acks = new IntArrayList();
            } else {
                acks.add((int) (rangeStart - cursor));
            }
            gaps.add((int) (cursor - lastLargest));
            acks.add(0);
        } else if (!firstPhase) {
            acks.add((int) (rangeStart - cursor));
        }

        if (!firstPhase) {
            assert acks.size() == gaps.size();

            this.ackRangeCount = acks.size();
            this.gaps = gaps.toArray(EMPTY_INT_ARR);
            this.acks = acks.toArray(EMPTY_INT_ARR);
        } else {
            this.ackRangeCount = 0;
            this.gaps = null;
            this.acks = null;
        }

        this.largestAckd = largestAckd;
        this.ackDelay = ackDelay;
        this.firstAck = firstAck;
    }

    public void write(ByteBuf out) {
        VariableInt.write(PACKET_ID, out);
        VariableInt.write(largestAckd, out);
        VariableInt.write(ackDelay, out);
        VariableInt.write(ackRangeCount, out);
        VariableInt.write(firstAck, out);
        for (int i = 0 ; i < ackRangeCount ; i++) {
            VariableInt.write(gaps[i], out);
            VariableInt.write(acks[i], out);
        }
    }

    public int length() {
        int length = 1 +
                VariableInt.length(largestAckd) +
                VariableInt.length(ackDelay) +
                VariableInt.length(ackRangeCount) +
                VariableInt.length(firstAck);
        for (int i = 0 ; i < ackRangeCount ; i++) {
            length += VariableInt.length(gaps[i]);
            length += VariableInt.length(acks[i]);
        }
        return length;
    }

    public void forEach(LongConsumer ack, LongConsumer gap) {
        long cursor = largestAckd;

        cursor = forEachRange(cursor, firstAck, ack);
        for (int i = 0 ; i < ackRangeCount ; i++) {
            cursor = forEachRange(cursor, gaps[i], gap);
            cursor = forEachRange(cursor, acks[i], ack);
        }
    }

    protected long forEachRange(long start, long length, LongConsumer consumer) {
        for (int i = 0 ; i < length ; i++) {
            consumer.accept(start--);
        }
        return start;
    }

    /*public static final class NackThrowable extends Throwable {
        public static final NackThrowable INSTANCE = new NackThrowable();

        private NackThrowable() {}

        @Override
        public Throwable initCause(Throwable cause)
        {
            return this;
        }

        @Override
        public Throwable fillInStackTrace()
        {
            return this;
        }
    }*/
}
