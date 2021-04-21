package ubiqfpe;

import java.util.Arrays;

import org.junit.Test;
import static org.junit.Assert.*;

public class FF3_1Test
{
    private void test(final byte[] key, final byte[] twk,
                      final String PT, final String CT,
                      final int radix) {
        String out;
        FF3_1 ctx;

        assertEquals(PT.length(), CT.length());

        ctx = new FF3_1(key, twk, radix);

        out = ctx.encrypt(PT);
        assertEquals(CT, out);

        out = ctx.decrypt(CT);
        assertEquals(PT, out);
    }

    private final byte[] key = {
        (byte)0xef, (byte)0x43, (byte)0x59, (byte)0xd8,
        (byte)0xd5, (byte)0x80, (byte)0xaa, (byte)0x4f,
        (byte)0x7f, (byte)0x03, (byte)0x6d, (byte)0x6f,
        (byte)0x04, (byte)0xfc, (byte)0x6a, (byte)0x94,
        (byte)0x3b, (byte)0x80, (byte)0x6a, (byte)0xeb,
        (byte)0x63, (byte)0x08, (byte)0x27, (byte)0x1f,
        (byte)0x65, (byte)0xcf, (byte)0x33, (byte)0xc7,
        (byte)0x39, (byte)0x1b, (byte)0x27, (byte)0xf7,
    };

    private final byte[] twk1 = {
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00,
    };
    private final byte[] twk2 = {
        (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
        (byte)0x35, (byte)0x34, (byte)0x33,
    };
    private final byte[] twk3 = {
        (byte)0x37, (byte)0x37, (byte)0x37, (byte)0x37,
        (byte)0x70, (byte)0x71, (byte)0x72,
    };

    private final String[] PT = {
        "890121234567890000", "89012123456789abcde"
    };

    @Test
    public void ubiq1() {
        this.test(Arrays.copyOf(this.key, 16),
                  this.twk1,
                  PT[0], "075870132022772250", 10);
    }

    @Test
    public void ubiq2() {
        this.test(Arrays.copyOf(this.key, 16),
                  this.twk2,
                  PT[0], "251467746185412673", 10);
    }

    @Test
    public void ubiq3() {
        test(Arrays.copyOf(this.key, 16),
             this.twk3,
             PT[1], "dwb01mx9aa2lmi3hrfm", 36);
    }

    @Test
    public void ubiq4() {
        test(Arrays.copyOf(this.key, 24),
             this.twk1,
             PT[0], "327701863379108161", 10);
    }

    @Test
    public void ubiq5() {
        test(Arrays.copyOf(this.key, 24),
             this.twk2,
             PT[0], "738670454850774517", 10);
    }

    @Test
    public void ubiq6() {
        test(Arrays.copyOf(this.key, 24),
             this.twk3,
             PT[1], "o3a1og390b5uduvwyw5", 36);
    }

    @Test
    public void ubiq7() {
        test(Arrays.copyOf(this.key, 32),
             this.twk1,
             PT[0], "892299037726855422", 10);
    }

    @Test
    public void ubiq8() {
        test(Arrays.copyOf(this.key, 32),
             this.twk2,
             PT[0], "045013216693726967", 10);
    }

    @Test
    public void ubiq9() {
        test(Arrays.copyOf(this.key, 32),
             this.twk3,
             PT[1], "0sxaooj0jjj5qqfomh8", 36);
    }
}
