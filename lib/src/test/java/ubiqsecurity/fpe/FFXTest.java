package ubiqsecurity.fpe;

import org.junit.Test;
import static org.junit.Assert.*;

import java.util.Arrays;

import java.math.BigInteger;

public class FFXTest
{
    @Test
    public void str() {
        String s;
        BigInteger i;

        s = FFX.str(5, 10, new BigInteger("12345", 10));
        assertEquals("12345", s);

        s = FFX.str(5, "0123456789", new BigInteger("12345", 10));
        assertEquals("12345", s);

        s = FFX.str(5, 10, FFX.DEFAULT_ALPHABET, new BigInteger("12345", 10));
        assertEquals("12345", s);

        s = FFX.str(6, 10, new BigInteger("12345", 10));
        assertEquals("012345", s);

        s = FFX.str(6, "0123456789", new BigInteger("12345", 10));
        assertEquals("012345", s);

        s = FFX.str(6, 10, FFX.DEFAULT_ALPHABET, new BigInteger("12345", 10));
        assertEquals("012345", s);

        s = FFX.str(6, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", new BigInteger("62", 10));
        assertEquals("000010", s);

        i = FFX.number("100", 10);
        assertEquals(i.compareTo(BigInteger.valueOf(100)), 0);

        i = FFX.number("100", 10, "0123456789");
        assertEquals(i.compareTo(BigInteger.valueOf(100)), 0);

        i = FFX.number("100", 10, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
        assertEquals(i.compareTo(BigInteger.valueOf(100)), 0);

        i = FFX.number("100", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
        assertEquals(i.compareTo(BigInteger.valueOf(62*62)), 0);

        i = FFX.number("z", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
        assertEquals(i.compareTo(BigInteger.valueOf(61)), 0);

        i = FFX.number("zz1", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
        assertEquals(i.compareTo(BigInteger.valueOf(1 + (61 * 62) + (61 * 62 * 62))), 0);

        s = FFX.str(3, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", i);
        assertEquals(s, "zz1");


        assertThrows(RuntimeException.class, () -> {
                FFX.str(4, 10, new BigInteger("12345", 10));
            });
    }

    @Test
    public void rev() {
        String s;
        byte[] b;

        b = FFX.rev(new byte[]{ 1, 2, 3, 4 });
        assertArrayEquals(new byte[]{ 4, 3, 2, 1 }, b);

        b = FFX.rev(new byte[]{ 1, 2, 3, 4, 5 });
        assertArrayEquals(new byte[]{ 5, 4, 3, 2, 1 }, b);

        s = FFX.rev("abcd");
        assertEquals("dcba", s);

        s = FFX.rev("abcde");
        assertEquals("edcba", s);
    }
}
