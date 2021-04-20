package ubiqfpe;

import org.junit.Test;
import static org.junit.Assert.*;

import java.util.Arrays;

import java.math.BigInteger;

public class FFXTest
{
    @Test
    public void str() {
        String s;

        s = FFX.str(5, 10, new BigInteger("12345", 10));
        assertEquals(s, "12345");

        s = FFX.str(6, 10, new BigInteger("12345", 10));
        assertEquals(s, "012345");

        assertThrows(RuntimeException.class, () -> {
                FFX.str(4, 10, new BigInteger("12345", 10));
            });
    }

    @Test
    public void rev() {
        String s;
        byte[] b;

        b = FFX.rev(new byte[]{ 1, 2, 3, 4 });
        assertArrayEquals(b, new byte[]{ 4, 3, 2, 1 });

        b = FFX.rev(new byte[]{ 1, 2, 3, 4, 5 });
        assertArrayEquals(b, new byte[]{ 5, 4, 3, 2, 1 });

        s = FFX.rev("abcd");
        assertEquals(s, "dcba");

        s = FFX.rev("abcde");
        assertEquals(s, "edcba");
    }
}
