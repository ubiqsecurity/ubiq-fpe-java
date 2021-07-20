package ubiqsecurity.fpe;

import java.io.IOException ;
import java.math.BigInteger;
 

/**
 * Algorithms to convert a numerical value in a given alphabet to a number
 */
 public class Bn {

    /**
     * Convert a numerical value in a given alphabet to a number.
     *
     * An alphabet consists of single-byte symbols in which each
     * symbol represents the numerical value associated with its
     * index/position in the alphabet. for example, consider the
     * alphabet: !@#$%^-*()
     * In this alphabet ! occupies index 0 and is therefore
     * assigned that value. @ = 1, # = 2, etc. Furthermore, the
     * alphabet contains 10 characters, so that becomes the radix
     * of the input. Using the alphabet above, an input of @$#
     * translates to a value of 132 (one hundred thirty-two,
     * decimal).
     *
     * If the alphabet above were instead: !@#$%^-*
     * The radix would be 8 and an input of @$# translates to a
     * value of 90 (ninety, decimal).
     *
     * @param str the numerical value to be converted
     * @param alpha alphabet consists of single-byte symbols
     *
     * @return the numerical value of the str pattern 
     * position found in the alphabet
     */
    public static BigInteger __bigint_set_str(final String str, final String alpha)
        {
            final int len = str.length();
            /*
             * the alphabet can be anything and doesn't have
             * to be in a recognized canonical order. the only
             * requirement is that every value in the list be
             * unique. checking that constraint is an expensive
             * undertaking, so it is assumed. as such, the radix
             * is simply the number of characters in the alphabet.
             */
            final int rad = alpha.length();

            BigInteger m, a;
            int i;
            BigInteger x;
            
            /* represents the numerical value of str */
            x = BigInteger.valueOf(0);
            /*
             * multiplier used to multiply each digit
             * of the input into its correct position
             */
            m = BigInteger.valueOf(1);
            
            for (i = 0; i < len; i++) {
                final int pos;
                /*
                 * determine index/position in the alphabet.
                 * if the character is not present the input
                 * is not valid.
                 */
                pos = alpha.indexOf(str.charAt(len - 1 - i));
                if (pos < 0) {
                    throw new IllegalArgumentException("invalid argument, input character not found in alphabet");
                }
                /*
                 * multiply the digit into the correct position
                 * and add it to the result
                 */
                a = m.multiply(BigInteger.valueOf(pos));
                x = x.add(a);
                m = m.multiply(BigInteger.valueOf(rad));
            }
            return x;
        }
    
    
    /**
     * Inserts a character at a position in a String.
     *
     * Convenience function returns String with inserted char 
     * at an index position.
     *
     * @param str the original String
     * @param ch the character to insert
     * @param position the index position where to insert the ch
     *
     * @return    the new String containing the inserted ch 
     */    
    public static String insertChar(String str, char ch, int position) {
        StringBuilder sb = new StringBuilder(str);
        sb.insert(position, ch);
        return sb.toString();
    }
    
    
    /**
     * Gets the str pattern of the alphabet given the numeric value.
     *
     * @param alpha alphabet consists of single-byte symbols
     * @param x the numerical value of the str pattern
     *
     * @return the new String of the converted value 
     */    
    public static String __bigint_get_str(final String alpha, final BigInteger x) {
        final int rad = alpha.length();
        BigInteger quotient;
        String str = "";
        
        /*
         * to convert the numerical value, repeatedly
         * divide (storing the resulted quotient and the remainder)
         * by the desired radix of the output.
         *
         * the remainder is the current digit; the result
         * of the division becomes the input to the next
         * iteration
         */
        final BigInteger len = BigInteger.valueOf(alpha.length());
        BigInteger positional = BigInteger.valueOf(1);
        quotient = x.multiply(positional);
        
        while (quotient.compareTo(BigInteger.valueOf(0)) != 0) {
            int remainder;
            
            BigInteger result[] = quotient.divideAndRemainder(BigInteger.valueOf(rad));
            remainder = result[1].intValue();
            quotient=  BigInteger.valueOf(result[0].intValue());
            str = insertChar(str, alpha.charAt(remainder), 0);
        }
        
        if (str.length() == 0) {
            str = insertChar(str, alpha.charAt(0), 0);
        }
                
        return str;
    }

}
















