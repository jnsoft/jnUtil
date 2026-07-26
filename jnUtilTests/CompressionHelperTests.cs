using jnUtil;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace jnUtilTests
{
    [TestClass]
    public class CompressionHelperTests
    {
        private static byte[] TextToBytes(string text) => Encoding.UTF8.GetBytes(text);
        private static string BytesToText(byte[] bytes) => Encoding.UTF8.GetString(bytes);

        [TestMethod]
        public void CompressDecompress_RoundTrip_ProducesOriginalData()
        {
            // Arrange
            byte[] original = TextToBytes("Hello, this is a test string for compression!");

            // Act
            byte[] compressed = CompressionHelper.Compress(original);
            byte[] decompressed = CompressionHelper.Decompress(compressed);

            // Assert
            CollectionAssert.AreEqual(original, decompressed);
        }

        [TestMethod]
        public void Compress_ProducesSmallerOutput_ForRepetitiveData()
        {
            // Arrange — repetitive data compresses well
            byte[] original = TextToBytes(new string('A', 10_000));

            // Act
            byte[] compressed = CompressionHelper.Compress(original);

            // Assert
            Assert.IsTrue(compressed.Length < original.Length,
                $"Compressed size ({compressed.Length}) should be smaller than original ({original.Length})");
        }

        [TestMethod]
        public void CompressDecompress_EmptyArray_RoundTrip()
        {
            // Arrange
            byte[] original = Array.Empty<byte>();

            // Act
            byte[] compressed = CompressionHelper.Compress(original);
            byte[] decompressed = CompressionHelper.Decompress(compressed);

            // Assert
            Assert.AreEqual(0, decompressed.Length);
        }

        [TestMethod]
        public void CompressDecompress_BinaryData_RoundTrip()
        {
            // Arrange
            byte[] original = new byte[256];
            for (int i = 0; i < original.Length; i++)
                original[i] = (byte)i;

            // Act
            byte[] compressed = CompressionHelper.Compress(original);
            byte[] decompressed = CompressionHelper.Decompress(compressed);

            // Assert
            CollectionAssert.AreEqual(original, decompressed);
        }

        [TestMethod]
        public void CompressDecompress_LargeData_RoundTrip()
        {
            // Arrange
            byte[] original = TextToBytes(new string('x', 1_000_000));

            // Act
            byte[] compressed = CompressionHelper.Compress(original);
            byte[] decompressed = CompressionHelper.Decompress(compressed);

            // Assert
            CollectionAssert.AreEqual(original, decompressed);
            Assert.IsTrue(compressed.Length < original.Length);
        }

        [TestMethod]
        public void GZipSingleFile_CompressAndDecompress_RoundTrip()
        {
            // Arrange
            string sourceFile = Path.GetTempFileName();
            string compressedFile = Path.GetTempFileName();
            string decompressedFile = Path.GetTempFileName();
            string originalText = "GZip file round-trip test content!";

            try
            {
                File.WriteAllText(sourceFile, originalText);

                // Act
                CompressionHelper.GZipSingeFile(sourceFile, compressedFile, zipNotUnzip: true);
                CompressionHelper.GZipSingeFile(compressedFile, decompressedFile, zipNotUnzip: false);

                // Assert
                string result = File.ReadAllText(decompressedFile);
                Assert.AreEqual(originalText, result);
                Assert.IsTrue(new FileInfo(compressedFile).Length > 0, "Compressed file should not be empty");
            }
            finally
            {
                File.Delete(sourceFile);
                File.Delete(compressedFile);
                File.Delete(decompressedFile);
            }
        }
    }

}

