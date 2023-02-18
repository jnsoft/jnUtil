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
            MemoryStream ms = new MemoryStream();
            GZipStream zip = new GZipStream(ms, CompressionMode.Compress, true);
            zip.Write(buffer, 0, buffer.Length);
            zip.Close();
            ms.Position = 0;

            byte[] compressed = new byte[ms.Length];
            ms.Read(compressed, 0, compressed.Length);

            byte[] gzBuffer = new byte[compressed.Length + 4];
            Buffer.BlockCopy(compressed, 0, gzBuffer, 4, compressed.Length);
            Buffer.BlockCopy(BitConverter.GetBytes(buffer.Length), 0, gzBuffer, 0, 4);
            return gzBuffer;
        }

        public static byte[] Decompress(byte[] gzBuffer)
        {
            MemoryStream ms = new MemoryStream();
            int msgLength = BitConverter.ToInt32(gzBuffer, 0);
            ms.Write(gzBuffer, 4, gzBuffer.Length - 4);

            byte[] buffer = new byte[msgLength];

            ms.Position = 0;
            GZipStream zip = new GZipStream(ms, CompressionMode.Decompress);
            zip.Read(buffer, 0, buffer.Length);

            return buffer;
        }

        // -> archive.gz | source = file to compress or uncompress, target = destination filename
        public static void GZipSingeFile(string source, string target, bool zipNotUnzip = true)
        {
            FileStream sourceFile = File.OpenRead(source);
            FileStream destFile;

            destFile = File.Create(target);
            GZipStream compStream;

            if (zipNotUnzip) // compress
            {
                compStream = new GZipStream(destFile, CompressionMode.Compress);
                try
                {
                    int theByte = sourceFile.ReadByte();
                    while (theByte != -1)
                    {
                        compStream.WriteByte((byte)theByte);
                        theByte = sourceFile.ReadByte();
                    }
                }
                finally
                {
                    compStream.Dispose();
                }
            }
            else // uncompress
            {
                compStream = new GZipStream(sourceFile, CompressionMode.Decompress);
                try
                {
                    int theByte = compStream.ReadByte();
                    while (theByte != -1)
                    {
                        destFile.WriteByte((byte)theByte);
                        theByte = compStream.ReadByte();
                    }
                }
                finally
                {
                    compStream.Dispose();
                }
            }
        }

        private static bool BitCheck(this byte b, int pos, bool zeroIndexed = true)
        {
            if (zeroIndexed)
                return (b & (1 << pos)) > 0;
            else
                return (b & (1 << (pos - 1))) > 0; // first bit = postition 1
        }

    }
}
