using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace jnUtil
{
    public static class CompressionHelper
    {
        public static byte[] Compress(byte[] buffer)
        {
            using MemoryStream ms = new MemoryStream();
            using (GZipStream zip = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
                zip.Write(buffer, 0, buffer.Length);

            byte[] compressed = ms.ToArray();

            byte[] gzBuffer = new byte[compressed.Length + 4];
            Buffer.BlockCopy(BitConverter.GetBytes(buffer.Length), 0, gzBuffer, 0, 4);
            Buffer.BlockCopy(compressed, 0, gzBuffer, 4, compressed.Length);
            return gzBuffer;
        }

        public static byte[] Decompress(byte[] gzBuffer)
        {
            int msgLength = BitConverter.ToInt32(gzBuffer, 0);

            using MemoryStream ms = new(gzBuffer, 4, gzBuffer.Length - 4);
            using GZipStream zip = new(ms, CompressionMode.Decompress);

            byte[] buffer = new byte[msgLength];
            zip.ReadExactly(buffer);

            return buffer;
        }

        // -> archive.gz | source = file to compress or uncompress, target = destination filename
        public static void GZipSingeFile(string source, string target, bool zipNotUnzip = true)
        {
            using FileStream sourceFile = File.OpenRead(source);
            using FileStream destFile = File.Create(target);

            if (zipNotUnzip) // compress
            {
                using GZipStream compStream = new GZipStream(destFile, CompressionMode.Compress);
                sourceFile.CopyTo(compStream);
            }
            else // uncompress
            {
                using GZipStream compStream = new GZipStream(sourceFile, CompressionMode.Decompress);
                compStream.CopyTo(destFile);
            }
        }

        private static bool bitCheck(this byte b, int pos, bool zeroIndexed = true)
        {
            if (zeroIndexed)
                return (b & (1 << pos)) > 0;
            else
                return (b & (1 << (pos - 1))) > 0; // first bit = postition 1
        }

    }
}
