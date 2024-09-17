using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace jnUtil
{
    public static class SecurityHelper
    {
        // key - secret
        // salt - not secret, but globally unique
        // IV - Initialization vector. Not secret, but never resued under same key, needs to be random for CBC. The difference between IV and nonce is that IV must be random and unpredictable.
        // nounce - "number used once", should never be repeated with same key, used in CTR mode and GCM. Does not have to be random or secret.

        #region Props

        public const int KEYSIZE = 256;
        public const int GCM_KEYSIZE = 256;
        public const int BUFFERSIZE = 1048576;

        private const int SALT_LEN = 16;

        private const string letters = "abcdefghijklmnopqrstuvwxyz";
        private const string numbers = "0123456789";
        private const string b64addon = "+/";
        private const string punctration = ".,!?:;";
        private const string complexChars = "_-*(){}[]<>#$%&@|=";

        private static string basicChars => letters + letters.ToUpper() + numbers;
        private static string base64chars => basicChars + b64addon;
        private static string allChars => base64chars + punctration + complexChars;

        #endregion

        #region String and Base 64

        // Binary to Base 64
        public static string ToBase64(this byte[] bytes, bool LineBreaks = true) => 
            Convert.ToBase64String(bytes, LineBreaks ? Base64FormattingOptions.InsertLineBreaks : Base64FormattingOptions.None);

        // Back to binary
        public static byte[] FromBase64(this string s) => Convert.FromBase64String(s);

        // byte[] to string
        public static byte[] ToBytes(this string s) => Encoding.UTF8.GetBytes(s);

        // byte[] to string
        public static string ToStringFromBytes(this byte[] arr) => Encoding.UTF8.GetString(arr);

        public static async Task Base64EncodeFile(string inputPath, string outputPath)
        {
            using FileStream inputFile = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.None, bufferSize: 1024 * 1024, useAsync: true); // When using `useAsync: true` you get better performance with buffers much larger than the default 4096 bytes.
            using CryptoStream base64Stream = new CryptoStream(inputFile, new ToBase64Transform(), CryptoStreamMode.Read);
            using FileStream outputFile = new FileStream(outputPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, bufferSize: 1024 * 1024, useAsync: true);
            await base64Stream.CopyToAsync(outputFile).ConfigureAwait(false);
        }

        public static async Task Base64DeccodeFile(string inputPath, string outputPath)
        {
            using FileStream inputFile = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.None, bufferSize: 1024 * 1024, useAsync: true); // When using `useAsync: true` you get better performance with buffers much larger than the default 4096 bytes.
            using CryptoStream base64Stream = new CryptoStream(inputFile, new FromBase64Transform(), CryptoStreamMode.Read);
            using FileStream outputFile = new FileStream(outputPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, bufferSize: 1024 * 1024, useAsync: true);
            await base64Stream.CopyToAsync(outputFile).ConfigureAwait(false);
        }

        #endregion

        #region Password and key generation

        public static string GetRandomPin(int len)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < len; i++)
                sb.Append(SecureRandom.RollDice(10) - 1);
            return sb.ToString();
        }

        public static byte[] GetRandomKey(int bytes_len) => RandomNumberGenerator.GetBytes(bytes_len);
        

        public static SecureString GeneratePassword(int len, bool complex)
        {
            string pot = complex ? allChars : basicChars;

            SecureString pass = new SecureString();
            for (int i = 0; i < len; i++)
                pass.AppendChar(pot[SecureRandom.RollDice((byte)pot.Length) - 1]);
            return pass;
        }

        // PBKDF2 - "random" bytes from password (Password-Based Key Derivation Function), salt=null uses default salt, 
        public static byte[] GetKeyFromPassword(SecureString password, byte[] salt, int keySizeInBytes = 32, int noOfIterations = 1000000)
        {
            if (salt == null)
                salt = new byte[] { 0x33, 0xa5, 0x17, 0xed, 0x3f, 0x4d, 0x8a, 0x64, 0x76, 0x65, 0x64, 0x39, 0xbf, 0x9d, 0x5d, 0x2c };

            IntPtr ptr = Marshal.SecureStringToBSTR(password);

            int length = Marshal.ReadInt32(ptr, -4);
            byte[] pwdByteArray = new byte[length];
            try
            {
                GCHandle handle = GCHandle.Alloc(pwdByteArray, GCHandleType.Pinned);
                try
                {
                    for (int i = 0; i < length; i++)
                        pwdByteArray[i] = Marshal.ReadByte(ptr, i);

                    using Rfc2898DeriveBytes key_PBKDF2 = new Rfc2898DeriveBytes(pwdByteArray, salt, noOfIterations, HashAlgorithmName.SHA256);
                    return key_PBKDF2.GetBytes(keySizeInBytes);
                }
                finally
                {
                    Array.Clear(pwdByteArray, 0, pwdByteArray.Length);
                    handle.Free();
                }
            }
            finally
            {
                Marshal.ZeroFreeBSTR(ptr);
            }
        }

        /// <summary>
        /// Using extract-then-expand paradigm: Extract psueudo-random key k from source key sk.
        /// RFC5869 HMAC-based Extract-and-Expand Key Derivation (HKDF)
        /// Never user a source key directly in a protocol, alwalys run sk through a KDF to get all the session keys needed.
        /// </summary>
        /// <param name="sourceKey"></param>
        /// <param name="context">Context must be unique for each application</param>
        /// <param name="len"></param>
        /// <param name="salt">Used when </param>
        /// <returns></returns>
        public static byte[] DeriveSessionKey_HKDF(byte[] sourceKey, byte[] context, int len_bytes, byte[] salt)
        {
            if (salt == null)
                salt = "1AD153B1146BCFF36AD1E30141157DAE195E8D9524F3EF2002458961C2BFBAA5".FromHexString(); // random

            byte[] output = new byte[len_bytes];
            int c = 0;
            int i = 0;

            // 1, Extract 
            using HMACSHA512 hmac = new HMACSHA512(salt); // yes, use salt as  key :)
            byte[] k = hmac.ComputeHash(sourceKey); // use source key as hmac data

            checked
            {
                // 2, Expand using HMAC as a PRF with key k
                using HMACSHA512 hmac2 = new HMACSHA512(k);
                while (len_bytes > 0)
                {
                    byte[] tk = hmac2.ComputeHash(context.ConcatArrays(BitConverter.GetBytes(i++)));
                    Array.Copy(tk, 0, output, c, Math.Min(len_bytes, tk.Length));
                    len_bytes -= tk.Length;
                    c += tk.Length;
                }
            }
            return output;
        }

        public static byte[] GetEntropy => GetEntropyFromGuid(Guid.NewGuid());

        private static byte[] GetEntropyFromGuid(Guid guid) => guid.ToByteArray();

        private static byte[] Get12ByteNounce()
        {
            long ticks = DateTimeHelper.TicksFrom1970();
            byte[] bytes = BitConverter.GetBytes(ticks);

            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);

            byte[] nounce = new byte[12];

            Array.Copy(bytes, 0, nounce, 4, 8);

            return nounce;

        }

        #endregion

        #region Checksum and MAC

        public static byte[] GetHash(MACTypes type, byte[] data)
        {
            if (type == MACTypes.MD5)
            {
                using (MD5 md5 = MD5.Create())
                    return md5.ComputeHash(data);
            }
            else if (type == MACTypes.SHA1)
            {
                using SHA1 sha = SHA1.Create();
                return sha.ComputeHash(data);
            }
            else if (type == MACTypes.SHA256)
            {
                using SHA256 sha = SHA256.Create();
                return sha.ComputeHash(data);
            }
            else if (type == MACTypes.SHA384)
            {
                using SHA384 sha = SHA384.Create();
                return sha.ComputeHash(data);
            }
            else if (type == MACTypes.SHA512)
            {
                using SHA512 sha = SHA512.Create();
                return sha.ComputeHash(data);
            }
            else
                return null;
        }

        public static bool VerifyHash(MACTypes type, byte[] data, byte[] hash)
        {
            byte[] hValue = GetHash(type, data);

            if (hash.Length != hValue.Length)
                return false;

            for (int i = 0; i < hash.Length; i++)
            {
                if (hValue[i] != hash[i])
                    return false;
            }
            return true;
        }

        public static byte[] GetMAC(MACTypes type, byte[] data, byte[] key)
        {
            if(type == MACTypes.MD5 && key.Length < 16)
                throw new ArgumentException("Minimun key length for MD5 MAC is 16 bytes");
            else if (type == MACTypes.SHA1 && key.Length < 20)
                throw new ArgumentException("Minimun key length for SHA-1 MAC is 20 bytes");
            else if (type == MACTypes.SHA256 && key.Length < 32)
                throw new ArgumentException("Minimun key length for SHA-256 MAC is 32 bytes");
            else if (type == MACTypes.SHA384 && key.Length < 48)
                throw new ArgumentException("Minimun key length for SHA-384 MAC is 48 bytes");
            else if (type == MACTypes.SHA512 && key.Length < 64)
                throw new ArgumentException("Minimun key length for SHA-512 MAC is 64 bytes");

            if (type == MACTypes.MD5)
            {
                using HMACMD5 md5 = new HMACMD5(key);
                return md5.ComputeHash(data);
            }
            else if (type == MACTypes.SHA1)
            {
                using HMACSHA1 sha = new HMACSHA1(key);
                return sha.ComputeHash(data);
            }
            else if (type == MACTypes.SHA256)
            {
                using HMACSHA256 sha = new HMACSHA256(key);
                return sha.ComputeHash(data);
            }
            else if (type == MACTypes.SHA384)
            {
                using HMACSHA384 sha = new HMACSHA384(key);
                return sha.ComputeHash(data);
            }
            else if (type == MACTypes.SHA512)
            {
                using HMACSHA512 sha = new HMACSHA512(key);
                return sha.ComputeHash(data);
            }
            else
                return null;
        }

        public static bool VerifyMAC(MACTypes type, byte[] data, byte[] key, byte[] MAC)
        {
            byte[] hValue = GetMAC(type, data, key);

            if (MAC.Length != hValue.Length)
                return false;

            bool test = true; // avoid timing attacks

            for (int i = 0; i < MAC.Length; i++)
            {
                if (hValue[i] != MAC[i])
                    test = false;
            }
            return test;
        }

        public enum MACTypes
        {
            MD5,
            SHA1,
            SHA256,
            SHA384,
            SHA512
        }

        #endregion

        #region Using OS (account) protection

        // wrapper for EncryptData_Account
        public static string EncryptString_Account(string input, byte[] extraEntropy = null)
        {
            byte[] encryptedData = EncryptData_Account(Encoding.Unicode.GetBytes(input), extraEntropy);
            input.ZeroString();
            return Convert.ToBase64String(encryptedData);
        }

        public static string DecryptString_Account(string encryptedData, byte[] extraEntropy = null)
        {
            try
            {
                byte[] decryptedData = DecryptData_Account(Convert.FromBase64String(encryptedData), extraEntropy);
                return Encoding.Unicode.GetString(decryptedData);
            }
            catch(Exception)
            {
                throw;
            }
        }

        public static byte[] EncryptData_Account(byte[] plain, byte[] extraEntropy = null)
        {
            byte[] encrypted = ProtectedData.Protect(plain, extraEntropy, DataProtectionScope.CurrentUser);
            Array.Clear(plain, 0, plain.Length);
            plain = null;
            return encrypted;
        }

        public static byte[] DecryptData_Account(byte[] encrypted, byte[] extraEntropy = null) => ProtectedData.Unprotect(encrypted, extraEntropy, DataProtectionScope.CurrentUser);

        public static void EncryptFile_Account(string path) => File.Encrypt(path);

        public static void DecryptFile_Account(string path) => File.Decrypt(path);

        #endregion

        #region Aes GCM

        // wrapper for GCMEncrypt
        public static byte[] GCMEncrypt(byte[] data, SecureString password, byte[] associatedData = null, int PBKDF2_iters = 1000000)
        {
            
            byte[] passwordSalt = GetRandomKey(SALT_LEN);
            byte[] key = GetKeyFromPassword(password, passwordSalt, GCM_KEYSIZE/8, PBKDF2_iters);
            
            var gcm_output = GCMEncrypt(data, key, associatedData);

            byte[] result = new byte[gcm_output.Length + passwordSalt.Length];

            int outputOffset = 0;

            ArrayHelper.Append(result, passwordSalt, ref outputOffset);
            ArrayHelper.Append(result, gcm_output, ref outputOffset);

            if (outputOffset != result.Length)
                throw new Exception("Offset doesn't match output length");

            return result;
        }

        // wrapper for GCMEncrypt
        public static byte[] GCMEncrypt(byte[] data, byte[] key, byte[] associatedData = null)
        {
            if (key == null || key.Length != GCM_KEYSIZE / 8)
                throw new ArgumentException($"Key must be 32 bytes");

            byte[] nounce = Get12ByteNounce();
            var gcm_output = GCMEncrypt(data, key, nounce, associatedData);

            byte[] result = new byte[gcm_output.Item1.Length + gcm_output.Item2.Length + nounce.Length];

            int outputOffset = 0;

            ArrayHelper.Append(result, nounce, ref outputOffset);
            ArrayHelper.Append(result, gcm_output.Item2, ref outputOffset); // 16 byte tag
            ArrayHelper.Append(result, gcm_output.Item1, ref outputOffset); // ciphertext

            if (outputOffset != result.Length)
                throw new Exception("Offset doesn't match output length");

            return result;
        }

        // wrapper for GCMDecrypt
        public static byte[] GCMDecrypt(byte[] encrypted, SecureString password, byte[] associatedData = null, int PBKDF2_iters = 1000000)
        {
            int pos = 0;
            byte[] passwordSalt = ArrayHelper.Extract(encrypted, SALT_LEN, ref pos);
            int enc_len = encrypted.Length - passwordSalt.Length;
            byte[] ciphertext = ArrayHelper.Extract(encrypted, enc_len, ref pos);

            byte[] key = GetKeyFromPassword(password, passwordSalt, GCM_KEYSIZE / 8, PBKDF2_iters);

            return GCMDecrypt(ciphertext, key, associatedData);
        }

        // wrapper for GCMDecrypt
        public static byte[] GCMDecrypt(byte[] encrypted, byte[] key, byte[] associatedData = null)
        {
            int pos = 0;
            byte[] nounce = ArrayHelper.Extract(encrypted, 12, ref pos);
            byte[] tag = ArrayHelper.Extract(encrypted, 16, ref pos);
            int enc_len = encrypted.Length - nounce.Length - tag.Length;
            byte[] ciphertext = ArrayHelper.Extract(encrypted, enc_len, ref pos);

            return GCMDecrypt(ciphertext, key, nounce, tag, associatedData);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="plain"></param>
        /// <param name="key"></param>
        /// <param name="nonce_12bytes"></param>
        /// <param name="associatedData"></param>
        /// <returns>(ciphertext, tag)</returns>
        public static (byte[], byte[]) GCMEncrypt(byte[] plain, byte[] key, byte[] nonce_12bytes, byte[] associatedData)
        {
            byte[] tag = new byte[16];
            byte[] ciphertext = new byte[plain.Length];

            using(AesGcm gcm = new(key, tag.Length))
            {
                gcm.Encrypt(nonce_12bytes, plain, ciphertext, tag, associatedData);
            }
            return (ciphertext, tag);
        }

        public static byte[] GCMDecrypt(byte[] ciphertext, byte[] key, byte[] nonce_12bytes, byte[] tag, byte[] associatedData)
        {
            byte[] plain = new byte[ciphertext.Length];

            using (AesGcm gcm = new(key, tag.Length))
            {
                gcm.Decrypt(nonce_12bytes, ciphertext, tag, plain, associatedData);
            }
            return plain;
        }

        #endregion

        #region AES 256 CBC Authenticated Encryption with Associated Data (AEAD)

        // wrapper for AEAD_Encrypt
        public static byte[] AEAD_Encrypt(SecureString pwd, byte[] pwdSalt, string msg) => 
            AEAD_Encrypt(GetKeyFromPassword(pwd, pwdSalt, 32), Encoding.UTF8.GetBytes(msg), AeCipher.Aes256CbcPkcs7);

        public static byte[] AEAD_Encrypt(SecureString pwd, byte[] pwdSalt, byte[] plain) =>
            AEAD_Encrypt(GetKeyFromPassword(pwd, pwdSalt, 32), plain, AeCipher.Aes256CbcPkcs7);

        // wrapper for AEAD_Decrypt
        public static byte[] AEAD_Decrypt(SecureString pwd, byte[] pwdSalt, byte[] encrypted) => 
            AEAD_Decrypt(GetKeyFromPassword(pwd, pwdSalt, 32), encrypted);

        // returns: cipher_algorithm_id || hmac_algorithm_id || hmac_tag || iv || ciphertext
        public static byte[] AEAD_Encrypt(byte[] key, byte[] data, AeCipher scheme)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Length < 16)
                throw new ArgumentOutOfRangeException(nameof(key), "Key must be at least 128 bits (16 bytes)");
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            AeHMac aeHMac = key.Length < 48 ? AeHMac.HMACSHA256 : AeHMac.HMACSHA512;

            byte[] algo = { (byte)scheme, (byte)aeHMac };
            byte[] iv;
            byte[] ciphertext;
            byte[] tag;

            using (HMAC tagGenerator = GetHMAC(aeHMac, key))
            {
                using (SymmetricAlgorithm cipher = GetCipher(scheme, key))
                using (ICryptoTransform encryptor = cipher.CreateEncryptor())
                {
                    iv = cipher.IV;
                    ciphertext = Transform(encryptor, data, 0, data.Length);
                }

                // IV and ciphertext both need to be included in the MAC
                tagGenerator.AppendData(algo);
                tagGenerator.AppendData(iv);
                tagGenerator.AppendData(ciphertext);
                tag = tagGenerator.GetHashAndReset();
            }

            int len = algo.Length + tag.Length + iv.Length + ciphertext.Length;

            byte[] output = new byte[len];
            int outputOffset = 0;

            ArrayHelper.Append(output, algo, ref outputOffset);
            ArrayHelper.Append(output, tag, ref outputOffset);
            ArrayHelper.Append(output, iv, ref outputOffset);
            ArrayHelper.Append(output, ciphertext, ref outputOffset);

            if (outputOffset != output.Length)
                throw new Exception("Offset doesn't match output length");

            return output;
        }

        public static byte[] AEAD_Decrypt(byte[] key, byte[] data)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Length < 16)
                throw new ArgumentOutOfRangeException(nameof(key), "Key must be at least 128 bits (16 bytes)");
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (data.Length < 2)
                throw new CryptographicException();

            AeCipher aeCipher = (AeCipher)data[0];
            AeHMac aeHMac = (AeHMac)data[1];

            using (SymmetricAlgorithm cipher = GetCipher(aeCipher, key))
            using (HMAC tagGenerator = GetHMAC(aeHMac, key))
            {
                int blockSizeInBytes = cipher.BlockSize / 8;
                int tagSizeInBytes = tagGenerator.HashSize / 8;
                int headerSizeInBytes = 2;
                int tagOffset = headerSizeInBytes;
                int ivOffset = tagOffset + tagSizeInBytes;
                int cipherTextOffset = ivOffset + blockSizeInBytes;
                int cipherTextLength = data.Length - cipherTextOffset;
                int minLen = cipherTextOffset + blockSizeInBytes;

                // minimum length is assumed public knowledge, nothing leaked here
                if (data.Length < minLen)
                    throw new CryptographicException();

                // Verify HMAC before proceeding to decrypt!
                tagGenerator.AppendData(data, 0, tagOffset);
                tagGenerator.AppendData(data, tagOffset + tagSizeInBytes, data.Length - tagSizeInBytes - tagOffset);
                byte[] generatedTag = tagGenerator.GetHashAndReset();
                if (!CryptographicEquals(generatedTag, 0, data, tagOffset, tagSizeInBytes))
                {
                    // Assuming every tampered message (of the same length) took the same
                    // amount of time to process, we can now safely say
                    // "this data makes no sense" without giving anything away.
                    throw new CryptographicException();
                }

                byte[] iv = new byte[blockSizeInBytes];
                Buffer.BlockCopy(data, ivOffset, iv, 0, iv.Length);
                cipher.IV = iv;

                using (ICryptoTransform decryptor = cipher.CreateDecryptor())
                {
                    return Transform(decryptor, data, cipherTextOffset, cipherTextLength);
                }
            }
        }

        private static byte[] Transform(ICryptoTransform transform, byte[] input, int inputOffset, int inputLength)
        {
            if (transform.CanTransformMultipleBlocks)
                return transform.TransformFinalBlock(input, inputOffset, inputLength);

            // else, let CryptoStream handle chunking
            using (MemoryStream messageStream = new MemoryStream())
            using (CryptoStream cryptoStream = new CryptoStream(messageStream, transform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(input, inputOffset, inputLength);
                cryptoStream.FlushFinalBlock();
                return messageStream.ToArray();
            }

        }

        /// <summary>
        /// Compare the contents of two arrays in an amount of time which is only
        /// dependent on <paramref name="length"/>.
        /// </summary>
        /// <param name="a">An array to compare to <paramref name="b"/>.</param>
        /// <param name="aOffset">
        /// The starting position within <paramref name="a"/> for comparison.
        /// </param>
        /// <param name="b">An array to compare to <paramref name="a"/>.</param>
        /// <param name="bOffset">
        /// The starting position within <paramref name="b"/> for comparison.
        /// </param>
        /// <param name="length">
        /// The number of bytes to compare between <paramref name="a"/> and
        /// <paramref name="b"/>.</param>
        /// <returns>
        /// <c>true</c> if both <paramref name="a"/> and <paramref name="b"/> have
        /// sufficient length for the comparison and all of the applicable values are the
        /// same in both arrays; <c>false</c> otherwise.
        /// </returns>
        /// <remarks>
        /// An "insufficient data" <c>false</c> response can happen early, but otherwise
        /// a <c>true</c> or <c>false</c> response take the same amount of time.
        /// </remarks>
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static bool CryptographicEquals(byte[] a, int aOffset, byte[] b, int bOffset, int length)
        {
            int result = 0;

            if (a.Length - aOffset < length || b.Length - bOffset < length)
            {
                return false;
            }

            unchecked
            {
                // Bitwise-OR of subtraction has been found to have the most
                // stable execution time.
                //
                // This cannot overflow because bytes are 1 byte in length, and
                // result is 4 bytes.
                // The OR propagates all set bytes, so the differences are only
                // present in the lowest byte.
                for (int i = 0; i < length; i++)
                    result = result | (a[i + aOffset] - b[i + bOffset]);
            }

            return result == 0;
        }

        // get HMAC object with key derived from input key
        private static HMAC GetHMAC(AeHMac aeMac, byte[] key)
        {
            HMAC hmac;

            switch (aeMac)
            {
                case AeHMac.HMACSHA256:
                    hmac = new HMACSHA256();
                    break;
                case AeHMac.HMACSHA512:
                    hmac = new HMACSHA512();
                    break;
                default:
                    throw new CryptographicException();
            }

            hmac.Key = key;

            // derive new key
            byte[] newKey = hmac.ComputeHash(new byte[] { 1, 77, 65, 67 }); // "null, m, a, c"
            hmac.Key = newKey;

            return hmac;
        }

        // Returns a configured SymmetricAlgorithm with key derived from input key
        private static SymmetricAlgorithm GetCipher(AeCipher aeCipher, byte[] key)
        {
            SymmetricAlgorithm symmetricAlgorithm;

            switch (aeCipher)
            {
                case AeCipher.Aes256CbcPkcs7:
                    symmetricAlgorithm = Aes.Create();
                    symmetricAlgorithm.KeySize = 256;
                    symmetricAlgorithm.Mode = CipherMode.CBC;
                    symmetricAlgorithm.Padding = PaddingMode.PKCS7;
                    symmetricAlgorithm.GenerateIV();
                    break;
                default:
                    throw new CryptographicException();
            }

            // derive key
            using (HMAC hmac = new HMACSHA256(key))
            {
                byte[] newkey = hmac.ComputeHash(new byte[] { 1, 99, 105, 112, 104, 101, 114 }); // "null, c, i, p, h, e, r"

                Array.Resize(ref newkey, symmetricAlgorithm.KeySize / 8);

                symmetricAlgorithm.Key = newkey;
            }

            return symmetricAlgorithm;
        }

        public enum AeCipher : byte
        {
            Unknown,
            Aes256CbcPkcs7,
        }

        public enum AeHMac : byte
        {
            Unknown,
            HMACSHA256,
            HMACSHA512
        }

        #endregion

        #region AES (old)

        // Wrapper for AesEncryptFile with key
        public static bool AesEncryptFile(string path, string outputPath, SecureString password)
        {
            if (!File.Exists(path))
                throw new ArgumentException("File does not exist");
            if (File.Exists(outputPath))
                throw new ArgumentException("Filename allready exists");

            byte[] salt = GetEntropy;

            byte[] key = GetKeyFromPassword(password, salt, 32);

            bool result = AesEncryptFile(path, outputPath, ref key, salt);
            ArrayHelper.ClearArray(ref key);
            return result;
        }

        // Combines passwordSalt || iv || ciphertext
        public static bool AesEncryptFile(string path, string outputPath, ref byte[] key, byte[] salt)
        {
            if (!File.Exists(path))
                throw new ArgumentException("File does not exist");
            if (File.Exists(outputPath))
                throw new ArgumentException("Filename allready exists");

            //create output file name
            using (FileStream fsCrypt = new FileStream(outputPath, FileMode.Create))
            {
                fsCrypt.Write(salt, 0, salt.Length);

                using (SymmetricAlgorithm aes = getAES(AesModes.Aes256CbcPkcs7, key))
                {
                    byte[] iv = aes.IV;
                    fsCrypt.Write(iv, 0, iv.Length);

                    using (CryptoStream cs = new CryptoStream(fsCrypt, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        using (FileStream fsIn = new FileStream(path, FileMode.Open))
                        {
                            //create a buffer (1mb) so only this amount will allocate in the memory and not the whole file
                            byte[] buffer = new byte[BUFFERSIZE];
                            int read;

                            try
                            {
                                while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                                    cs.Write(buffer, 0, read);

                                return true;
                            }
                            catch (Exception)
                            {
                                return false;
                            }
                        }
                    }
                }

            }
        }

        // Wrapper for AesDecryptFile with key
        public static bool AesDecryptFile(string path, string outputPath, SecureString password)
        {
            byte[] salt = AesGetSaltToDecryptFile(path);
            byte[] key = GetKeyFromPassword(password, salt, 32);
            bool result = AesDecryptFile(path, outputPath, ref key, GetEntropy.Length);
            ArrayHelper.ClearArray(ref key);
            return result;
        }

        // Reads passwordSalt || iv || ciphertext
        public static bool AesDecryptFile(string path, string outputPath, ref byte[] key, int saltLength)
        {
            byte[] salt = new byte[saltLength];
            byte[] iv = new byte[16];

            using (FileStream fsCrypt = new FileStream(path, FileMode.Open))
            {
                fsCrypt.Read(salt, 0, salt.Length);
                fsCrypt.Read(iv, 0, iv.Length);

                using (SymmetricAlgorithm aes = getAES(AesModes.Aes256CbcPkcs7, key, iv))
                {
                    using (CryptoStream cs = new CryptoStream(fsCrypt, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (FileStream fsOut = new FileStream(outputPath, FileMode.Create))
                        {
                            //create a buffer (1mb) so only this amount will allocate in the memory and not the whole file
                            byte[] buffer = new byte[BUFFERSIZE];
                            int read;

                            try
                            {
                                while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                                    fsOut.Write(buffer, 0, read);
                                return true;
                            }
                            catch (Exception)
                            {
                                return false;
                            }
                        }
                    }
                }

            }
        }

        public static byte[] AesGetSaltToDecryptFile(string path, int? saltlength = null)
        {
            if(!saltlength.HasValue)
                saltlength = GetEntropy.Length;
            
            byte[] salt = new byte[saltlength.Value];
           
            using (FileStream fsCrypt = new FileStream(path, FileMode.Open))
            {
                fsCrypt.Read(salt, 0, salt.Length);
            }
            return salt;
        }

        internal static SymmetricAlgorithm getAES(AesModes algo, byte[] key, byte[] IV = null)
        {
            SymmetricAlgorithm symmetricAlgorithm;

            symmetricAlgorithm = Aes.Create();

            symmetricAlgorithm.BlockSize = 128;

            if (algo.ToString().Contains("128"))
            {
                if (key.Length != 16)
                    throw new Exception("Key length missmatch!");

                symmetricAlgorithm.KeySize = 128;
            }
            else if (algo.ToString().Contains("256"))
            {
                if (key.Length != 32)
                    throw new Exception("Key length missmatch!");

                symmetricAlgorithm.KeySize = 256;
            }
            else
                throw new CryptographicException();


            if (algo.ToString().Contains("None"))
                symmetricAlgorithm.Padding = PaddingMode.None;

            else if (algo.ToString().Contains("Pkcs7"))
                symmetricAlgorithm.Padding = PaddingMode.PKCS7;

            else
                throw new CryptographicException();


            if (algo.ToString().Contains("Ecb"))
                symmetricAlgorithm.Mode = CipherMode.ECB;

            else if (algo.ToString().Contains("Cbc"))
                symmetricAlgorithm.Mode = CipherMode.CBC;

            else
                throw new CryptographicException();

            if (IV == null)
                symmetricAlgorithm.GenerateIV();
            else
                symmetricAlgorithm.IV = IV;

            symmetricAlgorithm.Key = key;

            return symmetricAlgorithm;
        }

        public enum AesModes : byte
        {
            Aes128EcbNone,
            Aes128EcbPkcs7,
            Aes128CbcNone,
            Aes128CbcPkcs7,
            Aes256EcbNone,
            Aes256EcbPkcs7,
            Aes256CbcNone,
            Aes256CbcPkcs7
        }

        #endregion

        #region PKI (Diffie-Hellman) crypto

        // returns private key and outputs public key
        public static byte[] GeneratePKIPair(out byte[] publicKey)
        {
            using (ECDiffieHellman dh = ECDiffieHellman.Create())
            {
                publicKey = dh.ExportSubjectPublicKeyInfo();
                return dh.ExportECPrivateKey();                
            }
        }

        // you need a generated key pair and the recievers public key
        public static byte[] DeriveSymmetricKey(byte[] myPrivateKey, byte[] otherPublicKey)
        {
            using (ECDiffieHellman ecdh = ECDiffieHellman.Create())
            {
                ecdh.ImportECPrivateKey(myPrivateKey, out _);
                using (ECDiffieHellman otherEcdh = ECDiffieHellman.Create())
                {
                    otherEcdh.ImportSubjectPublicKeyInfo(otherPublicKey, out _);
                    using ECDiffieHellmanPublicKey otherPublicKeyObj = otherEcdh.PublicKey;
                    return ecdh.DeriveKeyMaterial(otherPublicKeyObj);
                }
            }
        }

        #endregion

        #region Secure string

        public static string ToInsecureString(this SecureString secureStr) => new System.Net.NetworkCredential(string.Empty, secureStr).Password;

        public static SecureString ToSecureString(this string plainStr)
        {
            var ss = new System.Security.SecureString();
            ss.Clear();
            foreach (char c in plainStr.ToCharArray())
                ss.AppendChar(c);
            ss.MakeReadOnly();
            plainStr.ZeroString();
            return ss;
        }

        public static bool IsEqualTo(this SecureString ss1, SecureString ss2)
        {
            IntPtr bstr1 = IntPtr.Zero;
            IntPtr bstr2 = IntPtr.Zero;
            try
            {
                bstr1 = Marshal.SecureStringToBSTR(ss1);
                bstr2 = Marshal.SecureStringToBSTR(ss2);
                int length1 = Marshal.ReadInt32(bstr1, -4);
                int length2 = Marshal.ReadInt32(bstr2, -4);
                if (length1 == length2)
                {
                    for (int x = 0; x < length1; ++x)
                    {
                        byte b1 = Marshal.ReadByte(bstr1, x);
                        byte b2 = Marshal.ReadByte(bstr2, x);
                        if (b1 != b2)
                            return false;
                    }
                }
                else
                    return false;
                return true;
            }
            finally
            {
                if (bstr2 != IntPtr.Zero)
                    Marshal.ZeroFreeBSTR(bstr2);
                if (bstr1 != IntPtr.Zero)
                    Marshal.ZeroFreeBSTR(bstr1);
            }
        }

        #endregion

        #region Zero memory

        //  Call this function to remove the key from memory after use for security
        [DllImport("KERNEL32.DLL", EntryPoint = "RtlZeroMemory")]
        private static extern bool ZeroMemory(IntPtr Destination, int Length);

        public static bool ZeroString(this string s)
        {
            GCHandle gch = GCHandle.Alloc(s, GCHandleType.Pinned);
            bool res = ZeroMemory(gch.AddrOfPinnedObject(), s.Length * 2);
            gch.Free();
            return res;
        }

        #endregion

        #region Wipe file

        public static void WipeFile(string filename, int timesToWrite = 10, bool delete = true)
        {
            try
            {
                if (File.Exists(filename))
                {
                    // Set the files attributes to normal in case it's read-only.
                    File.SetAttributes(filename, FileAttributes.Normal);

                    // Calculate the total number of sectors in the file.
                    double sectors = Math.Ceiling(new FileInfo(filename).Length / 512.0);

                    // Create a dummy-buffer the size of a sector.
                    byte[] dummyBuffer = new byte[512];

                    // Create a cryptographic Random Number Generator.
                    // This is what I use to create the garbage data.
                    RandomNumberGenerator rng = RandomNumberGenerator.Create();

                    // Open a FileStream to the file.
                    FileStream inputStream = new FileStream(filename, FileMode.Open);

                    for (int currentPass = 0; currentPass < timesToWrite; currentPass++)
                    {
                        // Go to the beginning of the stream
                        inputStream.Position = 0;

                        // Loop all sectors
                        for (int sectorsWritten = 0; sectorsWritten < sectors; sectorsWritten++)
                        {
                            // Fill the dummy-buffer with random data
                            rng.GetBytes(dummyBuffer);
                            // Write it to the stream
                            inputStream.Write(dummyBuffer, 0, dummyBuffer.Length);
                        }
                    }

                    // Truncate the file to 0 bytes.
                    // This will hide the original file-length if you try to recover the file.
                    inputStream.SetLength(0);

                    // Close the stream.
                    inputStream.Close();

                    // As an extra precaution I change the dates of the file so the
                    // original dates are hidden if you try to recover the file.
                    DateTime dt = new DateTime(2037, 1, 1, 0, 0, 0);
                    File.SetCreationTime(filename, dt);
                    File.SetLastAccessTime(filename, dt);
                    File.SetLastWriteTime(filename, dt);

                    File.SetCreationTimeUtc(filename, dt);
                    File.SetLastAccessTimeUtc(filename, dt);
                    File.SetLastWriteTimeUtc(filename, dt);

                    if (delete)
                        File.Delete(filename);

                }
            }
            catch (Exception)
            {
                throw;
            }
        }

        public static void WipeDirectory(string path, int timesToWrite = 10, bool delete = true)
        {
            try
            {
                DirectoryInfo d = new DirectoryInfo(path);

                if (!d.Exists)
                    return;

                foreach (var dir in d.EnumerateDirectories())
                    WipeDirectory(dir.FullName, timesToWrite, delete);

                var files = d.GetFiles();
                foreach (var file in files)
                    WipeFile(file.FullName, timesToWrite, delete);

                d.Delete();
            }
            catch (Exception)
            {
                throw;
            }
        }

        #endregion

    }
}
