using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Text.Json;

namespace jnUtil
{
    public static class StreamHelper
    {
        public static byte[] GetBytesFromFile(string file)
        {
            using (FileStream fs = File.OpenRead(file))
            {
                byte[] bytes = new byte[fs.Length];
                fs.Read(bytes, 0, Convert.ToInt32(fs.Length));
                fs.Close();
                return bytes;
            }
        }

        public static void CopyStream(this Stream input, Stream output, Int64 len = 32768)
        {
            if (len == 32768)
            {
                byte[] b = new byte[32768];
                int r;
                while ((r = input.Read(b, 0, b.Length)) > 0)
                    output.Write(b, 0, r);
            }
            else //  repeatedly call read and move the position you will be storing the data at
            {
                byte[] b = new byte[len];
                int r, offset = 0;
                while ((r = input.Read(b, offset, b.Length - offset)) > 0)
                    offset += r;
            }
        }

        #region Stream to/from string

        public static string StreamToString(this Stream s)
        {
            using (StreamReader reader = new StreamReader(s))
            {
                return reader.ReadToEnd();
            }
        }

        public static Stream StringToStream(this string s)
        {
            byte[] byteArray = Encoding.UTF8.GetBytes(s);
            return new MemoryStream(byteArray);
        }

        #endregion

        #region Stream to/from Byte

        public static byte[] StreamToByte(Stream s) => ReadToEnd(s);

        // variant of StreamToByte - good if length is unknown
        public static byte[] ReadStream(this Stream input)
        {
            byte[] buffer = new byte[16 * 1024];
            using (MemoryStream ms = new MemoryStream())
            {
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    ms.Write(buffer, 0, read);
                }
                return ms.ToArray();
            }
        }

        public static Stream ByteToStream(byte[] bytes)
        {
            MemoryStream ms = new MemoryStream();
            ms.Write(bytes, 0, bytes.Length);
            return ms;
        }

        private static byte[] ReadToEnd(Stream stream)
        {
            long originalPosition = 0;

            if (stream.CanSeek)
            {
                originalPosition = stream.Position;
                stream.Position = 0;
            }

            try
            {
                byte[] readBuffer = new byte[4096];

                int totalBytesRead = 0;
                int bytesRead;

                while ((bytesRead = stream.Read(readBuffer, totalBytesRead, readBuffer.Length - totalBytesRead)) > 0)
                {
                    totalBytesRead += bytesRead;

                    if (totalBytesRead == readBuffer.Length)
                    {
                        int nextByte = stream.ReadByte();
                        if (nextByte != -1)
                        {
                            byte[] temp = new byte[readBuffer.Length * 2];
                            Buffer.BlockCopy(readBuffer, 0, temp, 0, readBuffer.Length);
                            Buffer.SetByte(temp, totalBytesRead, (byte)nextByte);
                            readBuffer = temp;
                            totalBytesRead++;
                        }
                    }
                }

                byte[] buffer = readBuffer;
                if (readBuffer.Length != totalBytesRead)
                {
                    buffer = new byte[totalBytesRead];
                    Buffer.BlockCopy(readBuffer, 0, buffer, 0, totalBytesRead);
                }
                return buffer;
            }
            finally
            {
                if (stream.CanSeek)
                {
                    stream.Position = originalPosition;
                }
            }
        }

        #endregion

        #region Serialization - requires [Serializable] attribute to classes

        public static MemoryStream SerializeToStream<T>(T o)
        {
            if(o == null)
                throw new ArgumentNullException(nameof(o),"Object cannot be null");
            var stream = new MemoryStream();
            JsonSerializer.Serialize(stream, o);
            stream.Position = 0;
            return stream;
        }

        public static byte[] SerializeToBytes<T>(T o) => JsonSerializer.SerializeToUtf8Bytes(o);

         public static T DeserializeFromStream<T>(MemoryStream stream)
        {
            stream.Position = 0;
            return JsonSerializer.Deserialize<T>(stream);
        }

        public static T DeserializeFromBytes<T>(byte[] bytes) => JsonSerializer.Deserialize<T>(bytes);
        

        #endregion

    }
}
