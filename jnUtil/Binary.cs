using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace jnUtil
{
    public static class Binary
    {
        public static string ToBinaryString(this byte[] bytes, bool LSBfirst = false, bool groupBytes = false)
        {
            BitArray bits = new BitArray(bytes);

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                if (LSBfirst)
                {
                    for (int j = 0; j < 8; j++)
                    {
                        char c = bits[i * 8 + j] ? '1' : '0';
                        sb.Append(c);
                    }
                }
                else
                {
                    for (int j = 0; j < 8; j++)
                    {
                        char c = bits[i * 8 + 7 - j] ? '1' : '0';
                        sb.Append(c);
                    }
                }
                if (groupBytes && i != bytes.Length - 1)
                    sb.Append(' ');
            }

            return sb.ToString();

        }

        // use BitConverter instead to convert to/from base datatypes to byte arrays
        public static string ToBitString(this BitArray bits)
        {
            var sb = new StringBuilder();

            for (int i = 0; i < bits.Count; i++)
            {
                char c = bits[i] ? '1' : '0';
                sb.Append(c);
            }

            return sb.ToString();
        }

        public static BitArray ToBitArray(this string bits)
        {
            BitArray arr = new BitArray(bits.Length);
            for (int i = 0; i < bits.Length; i++)
                arr[i] = bits[i] == '1' ? true : false;
            return arr;
        }

        // pad: 101 -> 00000101
        public static byte[] ToByteArray(this BitArray bits, bool pad = false)
        {
            byte[] ret = new byte[(bits.Length - 1) / 8 + 1];
            if (pad)
                bits = bits.Prepend(new BitArray(8 - bits.Length % 8));
            bits.CopyTo(ret, 0);
            return ret;
        }

        public static BitArray ToBitArray(this byte[] bytes) => new BitArray(bytes);

        public static BitArray Prepend(this BitArray current, BitArray before)
        {
            var bools = new bool[current.Count + before.Count];
            before.CopyTo(bools, 0);
            current.CopyTo(bools, before.Count);
            return new BitArray(bools);
        }

        public static BitArray Append(this BitArray current, BitArray after)
        {
            var bools = new bool[current.Count + after.Count];
            current.CopyTo(bools, 0);
            after.CopyTo(bools, current.Count);
            return new BitArray(bools);
        }

        // pad: 00000101 -> 101
        public static BitArray Trim(this BitArray arr)
        {
            int c = 0;
            while (arr[c] == false && c != arr.Length - 1)
                c++;
            var bools = new bool[arr.Length - c];
            for (int i = 0; i < bools.Length; i++)
                bools[i] = arr[i + c];
            return new BitArray(bools);
        }

        

    }
}
