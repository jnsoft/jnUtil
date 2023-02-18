using System;
using System.Collections.Generic;
using System.Text;

namespace jnUtil
{
    public static class Hex
    {
        public static string ToHexString(this byte[] bytes, bool toLower = false)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
                sb.Append(bytes[i].ToString(toLower ? "x2" : "X2"));
            return sb.ToString();
        }

        public static string ToHexString(this int i, bool lower = true, int pad = 0)
        {
            string size = "";
            if (pad != 0)
                size = pad.ToString();
            if (lower)
                return i.ToString("x" + size);
            else
                return i.ToString("X" + size);
        }

        public static byte[] FromHexString(this string hex)
        {
            if (hex.Length % 2 == 1)
                throw new ArgumentException($"The string cannot have an odd number of digits, string length: {hex.Length}");

            byte[] arr = new byte[hex.Length >> 1];

            for (int i = 0; i < hex.Length >> 1; ++i)
            {
                arr[i] = (byte)((getHexVal(hex[i << 1]) << 4) + (getHexVal(hex[(i << 1) + 1])));
            }
            return arr;
        }

        // wrapper for Xor(byte[]...)
        public static string Xor(this string s, string key, bool lowerHex = false)
        {
            byte[] xor = s.ToByte().Xor(key.ToByte(), true);
            return xor.ToHexString(lowerHex);
        }

        // expand: use b many times to get same length (key expansion)
        public static byte[] Xor(this byte[] a, byte[] b, bool expand = true)
        {
            if (a == null || b == null)
                return null;

            int len = Math.Max(a.Length, b.Length);

            byte[] res = new byte[len];

            if (expand)
            {
                a.CopyTo(res, 0);
                for (int i = 0; i < a.Length; i++)
                    res[i] ^= b[i % (b.Length)];
            }
            else if (a.Length > b.Length)
            {
                a.CopyTo(res, 0);
                for (int i = 0; i < b.Length; i++)
                    res[i] ^= b[i];
            }
            else
            {
                b.CopyTo(res, 0);
                for (int i = 0; i < a.Length; i++)
                    res[i] ^= a[i];
            }

            return res;
        }

        private static int getHexVal(char hex)
        {
            int val = (int)hex;
            // return val - (val < 58 ? 48 : 55);  // uppercase A-F
            //return val - (val < 58 ? 48 : 87); // // lowercase a-f
            return val - (val < 58 ? 48 : (val < 97 ? 55 : 87)); // combined, slower
        }
    }
}
