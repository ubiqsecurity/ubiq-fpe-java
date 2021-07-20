package ubiqsecurity.fpe;

import org.junit.Test;
import static org.junit.Assert.*;
import java.math.BigInteger;

public class BnTest
{
    @Test
    public void radix_exceptions() {
        /* exception test for bad input */
        assertThrows(RuntimeException.class, () -> {
            Bn.__bigint_set_str("109", "012345678");
        });
        
        assertThrows(RuntimeException.class, () -> {
            Bn.__bigint_get_str("", BigInteger.valueOf(0));
        });
    }


    @Test
    public void radix_edgecase() {
        /* 0 test */
        BigInteger r1 = Bn.__bigint_set_str("0", "0123456789");
        assertEquals(r1, BigInteger.valueOf(0));

        String output = Bn.__bigint_get_str("0123456789ABCDEF", r1);
        assertEquals(output, "0");
        
        output = Bn.__bigint_get_str("0123456789ABCDEF", BigInteger.valueOf(0));
        assertEquals(output, "0");
    }


    @Test
    public void radix_dec2hex() {
        /* dec2hex */
        BigInteger r1 = Bn.__bigint_set_str("100", "0123456789");
        assertEquals(r1, BigInteger.valueOf(100));

        String output = Bn.__bigint_get_str("0123456789ABCDEF", r1);
        assertEquals(output, "64");
    }


    @Test
    public void radix_oct2hex() {
        /* oct2hex */
        BigInteger r1 = Bn.__bigint_set_str("100", "01234567");
        assertEquals(r1, BigInteger.valueOf(64));

        String output = Bn.__bigint_get_str("0123456789ABCDEF", r1);
        assertEquals(output, "40");
    }


    @Test
    public void radix_dec2dec() {
        /* dec2dec */
        BigInteger r1 = Bn.__bigint_set_str("@$#", "!@#$%^&*()");
        assertEquals(r1, BigInteger.valueOf(132));

        String output = Bn.__bigint_get_str("0123456789", r1);
        assertEquals(output, "132");
    }


    @Test
    public void radix_oct2dec() {
        /* oct2dec */
        BigInteger r1 = Bn.__bigint_set_str("@$#", "!@#$%^&*");
        assertEquals(r1, BigInteger.valueOf(90));

        String output = Bn.__bigint_get_str("0123456789", r1);
        assertEquals(output, "90");
    }
}
