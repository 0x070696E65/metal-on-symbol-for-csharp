using System.Numerics;
using System.Text;

namespace MetalForSymbol.utils;

public static class Base58Encoding
{
    private const string base58Chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    public static string Encode(byte[]? data)
    {
        if (data == null || data.Length == 0) {
            return string.Empty;
        }

        // Count leading zeros.
        var leadingZeros = 0;
        while (leadingZeros < data.Length && data[leadingZeros] == 0)
        {
            leadingZeros++;
        }

        // Convert to base-58.
        var builder = new StringBuilder();
        var value = new BigInteger(data.Reverse().ToArray());
        while (value > 0)
        {
            var remainder = value % 58;
            builder.Insert(0, base58Chars[(int)remainder]);
            value /= 58;
        }

        // Add leading zeros.
        builder.Insert(0, new string(base58Chars[0], leadingZeros));

        return builder.ToString();
    }
    
    public static byte[] Decode(string encoded)
    {
        if (string.IsNullOrEmpty(encoded)) {
            return Array.Empty<byte>();
        }

        // Count leading zeros.
        var leadingZeros = 0;
        while (leadingZeros < encoded.Length && encoded[leadingZeros] == base58Chars[0])
        {
            leadingZeros++;
        }

        // Convert from base-58.
        BigInteger value = 0;
        for (var i = leadingZeros; i < encoded.Length; i++)
        {
            var digit = base58Chars.IndexOf(encoded[i]);
            if (digit < 0) {
                throw new FormatException("Invalid Base58 character encountered in input");
            }

            value = value * 58 + digit;
        }

        var data = value.ToByteArray().Reverse().ToArray();

        // Remove leading zeros.
        var leadingZeroCount = 0;
        while (leadingZeroCount < data.Length && data[leadingZeroCount] == 0)
        {
            leadingZeroCount++;
        }

        // Add back leading zeros.
        var output = new byte[leadingZeros + data.Length - leadingZeroCount];
        for (var i = 0; i < leadingZeros; i++) {
            output[i] = 0;
        }

        Array.Copy(data, leadingZeroCount, output, leadingZeros, data.Length - leadingZeroCount);
        return output;
    }
}
