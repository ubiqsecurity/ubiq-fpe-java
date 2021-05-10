package ubiqsecurity.fpe;

import java.util.Arrays;

import org.junit.Test;
import static org.junit.Assert.*;

public class FF1Test
{
    private void test(final byte[] key, final byte[] twk,
                      final String PT, final String CT,
                      final int radix) {
        String out;
        FF1 ctx;

        assertEquals(PT.length(), CT.length());

        ctx = new FF1(key, twk, 0, 0, radix);

        out = ctx.encrypt(PT);
        assertEquals(CT, out);

        out = ctx.decrypt(CT);
        assertEquals(PT, out);
    }

    private final byte[] key = {
        (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
        (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
        (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
        (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c,
        (byte)0xef, (byte)0x43, (byte)0x59, (byte)0xd8,
        (byte)0xd5, (byte)0x80, (byte)0xaa, (byte)0x4f,
        (byte)0x7f, (byte)0x03, (byte)0x6d, (byte)0x6f,
        (byte)0x04, (byte)0xfc, (byte)0x6a, (byte)0x94,
    };

    private final byte[] twk1 = {};
    private final byte[] twk2 = {
        (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
        (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
        (byte)0x31, (byte)0x30,
    };
    private final byte[] twk3 = {
        (byte)0x37, (byte)0x37, (byte)0x37, (byte)0x37,
        (byte)0x70, (byte)0x71, (byte)0x72, (byte)0x73,
        (byte)0x37, (byte)0x37, (byte)0x37,
    };

    private final String[] PT = {
        "0123456789", "0123456789abcdefghi"
    };

    @Test
    public void nist1() {
        this.test(Arrays.copyOf(this.key, 16),
                  this.twk1,
                  PT[0], "2433477484", 10);
    }

    @Test
    public void nist2() {
        this.test(Arrays.copyOf(this.key, 16),
                  this.twk2,
                  PT[0], "6124200773", 10);
    }

    @Test
    public void nist3() {
        test(Arrays.copyOf(this.key, 16),
             this.twk3,
             PT[1], "a9tv40mll9kdu509eum", 36);
    }

    @Test
    public void nist4() {
        test(Arrays.copyOf(this.key, 24),
             this.twk1,
             PT[0], "2830668132", 10);
    }

    @Test
    public void nist5() {
        test(Arrays.copyOf(this.key, 24),
             this.twk2,
             PT[0], "2496655549", 10);
    }

    @Test
    public void nist6() {
        test(Arrays.copyOf(this.key, 24),
             this.twk3,
             PT[1], "xbj3kv35jrawxv32ysr", 36);
    }

    @Test
    public void nist7() {
        test(Arrays.copyOf(this.key, 32),
             this.twk1,
             PT[0], "6657667009", 10);
    }

    @Test
    public void nist8() {
        test(Arrays.copyOf(this.key, 32),
             this.twk2,
             PT[0], "1001623463", 10);
    }

    @Test
    public void nist9() {
        test(Arrays.copyOf(this.key, 32),
             this.twk3,
             PT[1], "xs8a0azh2avyalyzuwd", 36);
    }
}
