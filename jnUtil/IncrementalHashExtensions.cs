using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace jnUtil
{
    internal static class IncrementalHashExtensions
    {
        public static void AppendData(this HashAlgorithm hash, byte[] data) =>
            hash.TransformBlock(data, 0, data.Length, null, 0);

        public static void AppendData(this HashAlgorithm hash, byte[] data, int offset, int length) =>
            hash.TransformBlock(data, offset, length, null, 0);
        
        public static byte[] GetHashAndReset(this HashAlgorithm hash)
        {
            hash.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            return hash.Hash;
        }
    }
}
