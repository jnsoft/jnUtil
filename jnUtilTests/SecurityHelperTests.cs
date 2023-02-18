using jnUtil;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Security;
using System.Text;

namespace jnUtilTests
{
    [TestClass]
    public class SecurityHelperTests
    {
        [TestMethod]
        public void StringToBytesTests()
        {
            // Arrange
            string inputText = "this is a text";

            // Act
            byte[] bytes = inputText.ToBytes();
            string outputText = bytes.ToStringFromBytes();
            
            // Assert
            Assert.AreEqual(inputText, outputText, "String to bytes and back failed");
        }

        [TestMethod]
        public void Base64Tests()
        {
            // Arrange
            string inputText = "plain text";

            // Act
            string b64 = inputText.ToBytes().ToBase64();
            string outputText = b64.FromBase64().ToStringFromBytes();

            // Assert
            Assert.AreEqual(inputText, outputText, "Base64 encoding/decoding falied");
        }

        [TestMethod]
        public void Base64FileTests()
        {
            // Arrange
            string inputText = "plain text";
            string fname = SecurityHelper.GetRandomPin(20);
            File.WriteAllText(fname + ".txt", inputText);

            // Act
            SecurityHelper.Base64EncodeFile(fname + ".txt", fname + ".b64").Wait();
            SecurityHelper.Base64DeccodeFile(fname + ".b64", fname + "_2.txt").Wait();
            string fileContent = File.ReadAllText(fname + "_2.txt");
            File.Delete(fname + ".txt");
            File.Delete(fname + ".b64");
            File.Delete(fname + "_2.txt");

            // Assert
            Assert.AreEqual(inputText, fileContent, "Base64 encoding/decoding file falied");
        }

        [TestMethod]
        public void PasswordGenerationTests()
        {
            // Arrange
            SecureString password = SecurityHelper.GeneratePassword(12,true);
            byte[] salt = SecurityHelper.GetRandomKey(32);

            // Act
            byte[] key = SecurityHelper.GetKeyFromPassword(password, salt, 32, 100000);
            byte[] key2 = SecurityHelper.GetKeyFromPassword(password, salt, 32, 100000);
            byte[] key3 = SecurityHelper.GetKeyFromPassword(password, salt, 32, 100001);

            // Assert
            CollectionAssert.AreEqual(key, key2, "Key generation from password not deterministic");
            CollectionAssert.AreNotEqual(key, key3, "Key generation from password not dependent on iterations");
        }

        [TestMethod]
        public void HashTests()
        {
            // Arrange
            string inputString = "abc";
            string MD5hash = "900150983CD24FB0D6963F7D28E17F72";
            string Sha1Hash = "a9993e364706816aba3e25717850c26c9cd0d89d";
            string Sha256Hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
            string Sha384Hash = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7";
            string Sha512Hash = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
            
            byte[] testVector = inputString.ToBytes();

            // Act
            byte[] md5 = SecurityHelper.GetHash(SecurityHelper.MACTypes.MD5,testVector);
            byte[] sha1 = SecurityHelper.GetHash(SecurityHelper.MACTypes.SHA1, testVector);
            byte[] sha256 = SecurityHelper.GetHash(SecurityHelper.MACTypes.SHA256, testVector);
            byte[] sha384 = SecurityHelper.GetHash(SecurityHelper.MACTypes.SHA384, testVector);
            byte[] sha512 = SecurityHelper.GetHash(SecurityHelper.MACTypes.SHA512, testVector);

            // Assert
            Assert.AreEqual(MD5hash, md5.ToHexString(), "MD5 hash failed");
            Assert.AreEqual(Sha1Hash, sha1.ToHexString(true), "SHA-1 hash failed");
            Assert.AreEqual(Sha256Hash, sha256.ToHexString(true), "SHA-256 hash failed");
            Assert.AreEqual(Sha384Hash, sha384.ToHexString(true), "SHA-384 hash failed");
            Assert.AreEqual(Sha512Hash, sha512.ToHexString(true), "SHA-512 hash failed");

            Assert.IsTrue(SecurityHelper.VerifyHash(SecurityHelper.MACTypes.MD5, testVector, md5));
            Assert.IsTrue(SecurityHelper.VerifyHash(SecurityHelper.MACTypes.SHA1, testVector, sha1));
            Assert.IsTrue(SecurityHelper.VerifyHash(SecurityHelper.MACTypes.SHA256, testVector, sha256));
            Assert.IsTrue(SecurityHelper.VerifyHash(SecurityHelper.MACTypes.SHA384, testVector, sha384));
            Assert.IsTrue(SecurityHelper.VerifyHash(SecurityHelper.MACTypes.SHA512, testVector, sha512));
        }

        [TestMethod]
        public void MacTests()
        {
            // Arrange
            string inputString = "abc";
            byte[] testVector = inputString.ToBytes();
            byte[] key = SecurityHelper.GetRandomKey(64);
            
            // Act
            byte[] md5 = SecurityHelper.GetMAC(SecurityHelper.MACTypes.MD5, testVector,key);
            byte[] sha1 = SecurityHelper.GetMAC(SecurityHelper.MACTypes.SHA1, testVector, key);
            byte[] sha256 = SecurityHelper.GetMAC(SecurityHelper.MACTypes.SHA256, testVector, key);
            byte[] sha384 = SecurityHelper.GetMAC(SecurityHelper.MACTypes.SHA384, testVector, key);
            byte[] sha512 = SecurityHelper.GetMAC(SecurityHelper.MACTypes.SHA512, testVector, key);

            // Assert
            Assert.IsTrue(SecurityHelper.VerifyMAC(SecurityHelper.MACTypes.MD5, testVector, key, md5));
            Assert.IsTrue(SecurityHelper.VerifyMAC(SecurityHelper.MACTypes.SHA1, testVector, key, sha1));
            Assert.IsTrue(SecurityHelper.VerifyMAC(SecurityHelper.MACTypes.SHA256, testVector, key, sha256));
            Assert.IsTrue(SecurityHelper.VerifyMAC(SecurityHelper.MACTypes.SHA384, testVector, key, sha384));
            Assert.IsTrue(SecurityHelper.VerifyMAC(SecurityHelper.MACTypes.SHA512, testVector, key, sha512));
        }

        [TestMethod]
        public void OSEncryptDecryptStringsTest()
        {
            // Arrange
            string message = "secret message";
            string message2 = "s" + message.Substring(1); // force different reference for string

            // Act
            string encrypted = SecurityHelper.EncryptString_Account(message);
            string decrypted = SecurityHelper.DecryptString_Account(encrypted);

            // Assert
            Assert.AreEqual(message2, decrypted, $"'{message2}' vs '{decrypted}'");
            Assert.AreNotEqual(message, decrypted, $"Zero string failed");

        }

        [TestMethod]
        public void OSEncryptDecryptTest()
        {
            // Arrange
            byte[] plain = new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 };
            byte[] org = new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5 };

            // Act
            byte[] encrypted = SecurityHelper.EncryptData_Account(plain);
            byte[] decrypted = SecurityHelper.DecryptData_Account(encrypted);

            // Assert
            CollectionAssert.AreEqual(org, decrypted);
            CollectionAssert.AreNotEquivalent(plain, decrypted);
        }

        // test creation, extraction and comparing of secure strings and zero-out of orginal string
        [TestMethod]
        public void SecureStringTests()
        {
            // Arrange
            string org = "test";
            string input = GenericCopier<string>.DeepCopy(org);
            string input2 = GenericCopier<string>.DeepCopy(org);
            
            // Act
            SecureString inputSS = input.ToSecureString();
            SecureString inputSS2 = input2.ToSecureString();
            string output = inputSS.ToInsecureString();
            bool isEqual = inputSS.IsEqualTo(inputSS2);

            // Assert
            Assert.AreNotEqual(input, output, "Secure string zero function falied");
            Assert.AreEqual(org, output, "Secure string creation/extraction falied");
            Assert.IsTrue(isEqual, "Secure string comparer failed");
        }

        [TestMethod]
        public void GCM_Tests()
        {
            // Arrange
            byte[] plaintext = Encoding.UTF8.GetBytes("secret message");

            byte[] key = SecurityHelper.GetRandomKey(32);
            byte[] key2 = SecurityHelper.GetRandomKey(32);

            byte[] nonce = new byte[12];
            nonce[nonce.Length - 1] = (byte)1;

            byte[] ad = Encoding.UTF8.GetBytes("This is id 5"); // associated data, can be null
            byte[] ad2 = Encoding.UTF8.GetBytes("This is id 4");

            bool differentKey = false;
            bool differentAD = false;

            // Act
            (byte[] encrypted, byte[] tag) = SecurityHelper.GCMEncrypt(plaintext, key, nonce, ad);
            byte[] decrypted = SecurityHelper.GCMDecrypt(encrypted, key, nonce, tag, ad);

            try
            {
                byte[] decrypted_differentKey = SecurityHelper.GCMDecrypt(encrypted, key2, nonce, tag, ad);
                differentKey = true;
            }
            catch (System.Exception) { }

            try
            {
                byte[] decrypted_differentAD = SecurityHelper.GCMDecrypt(encrypted, key, nonce, tag, ad2);
                differentAD = true;
            }
            catch (System.Exception) { }

            // Assert
            CollectionAssert.AreEqual(plaintext, decrypted);
            Assert.IsFalse(differentKey);
            Assert.IsFalse(differentAD);
        }

        [TestMethod]
        public void GCM_Wrapper_Tests()
        {
            // Arrange
            SecureString password = "my secret key".ToSecureString();
            byte[] plaintext = Encoding.UTF8.GetBytes("secret message");

            byte[] key = SecureRandom.GetRandomBytes(32);
            byte[] associatedData = SecureRandom.GetRandomBytes(128);

            // Act
            byte[] encrypted = SecurityHelper.GCMEncrypt(plaintext, key, associatedData);
            byte[] decrypted = SecurityHelper.GCMDecrypt(encrypted, key, associatedData);

            byte[] encrypted2 = SecurityHelper.GCMEncrypt(plaintext, password, null, 100000);
            byte[] decrypted2 = SecurityHelper.GCMDecrypt(encrypted2, password, null, 100000);

            // Assert
            CollectionAssert.AreEqual(plaintext, decrypted);
            CollectionAssert.AreEqual(plaintext, decrypted2);
        }

        [TestMethod]
        public void AEAD_EncryptDecryptTests()
        {
            // Arrange
            string msg = "secret message";
            byte[] plaintext = Encoding.UTF8.GetBytes(msg);
            byte[] salt = "this is salt".ToBytes();
            byte[] key = SecurityHelper.GetRandomKey(32);
            SecureString password = "password".ToSecureString();

            // Act
            byte[] encrypted = SecurityHelper.AEAD_Encrypt(key, plaintext, SecurityHelper.AeCipher.Aes256CbcPkcs7);
            byte[] decrypted = SecurityHelper.AEAD_Decrypt(key, encrypted);
            byte[] encrypted2 = SecurityHelper.AEAD_Encrypt(password, salt, msg);
            byte[] decrypted2 = SecurityHelper.AEAD_Decrypt(password, salt, encrypted2);

            // Assert
            CollectionAssert.AreEqual(plaintext, decrypted, "Encryption / decryption with key failed");
            CollectionAssert.AreEqual(plaintext, decrypted2, "Encryption / decryption with password failed");
        }

        [TestMethod]
        public void FileEncryptionWithPasswordTests()
        {
            // Arrange
            string fname = SecurityHelper.GetRandomPin(20);
            SecureString pass = "password".ToSecureString();
            string msg = "test";
            File.WriteAllText(fname + ".txt", msg);

            // Act
            SecurityHelper.AesEncryptFile(fname + ".txt", fname + ".enc", pass);
            SecurityHelper.AesDecryptFile(fname + ".enc", fname + ".txt", pass);
            string fileContent = File.ReadAllText(fname + ".txt");
            File.Delete(fname + ".txt");
            File.Delete(fname + ".enc");

            // Assert
            Assert.AreEqual(msg, fileContent);
        }

        [TestMethod]
        public void FileEncryptionWithKeyTests()
        {
            // Arrange
            string fname = SecurityHelper.GetRandomPin(20);
            byte[] key = SecurityHelper.GetRandomKey(32);
            byte[] salt = SecurityHelper.GetRandomKey(16);
            string msg = "test";
            File.WriteAllText(fname + ".txt", msg);
            string plainFile = fname + ".txt";
            string encFile = fname + ".enc";

            // Act
            SecurityHelper.AesEncryptFile(plainFile, encFile, ref key, salt);
            byte[] salt2 = SecurityHelper.AesGetSaltToDecryptFile(encFile);
            SecurityHelper.AesDecryptFile(encFile, plainFile, ref key, salt2.Length);
            string fileContent = File.ReadAllText(plainFile);
            File.Delete(plainFile);
            File.Delete(encFile);

            // Assert
            CollectionAssert.AreEqual(salt, salt2);
            Assert.AreEqual(msg, fileContent);
        }

        [TestMethod]
        public void PKI_DeriveKeyTest()
        {
            // Arrange
            byte[] BobPublicKey = null;
            byte[] AlicePublicKey = null;

            byte[] BobPrivateKey = null; 
            byte[] AlicePrivateKey = null; 

            // Act
            AlicePrivateKey = SecurityHelper.GeneratePKIPair(out AlicePublicKey);
            BobPrivateKey = SecurityHelper.GeneratePKIPair(out BobPublicKey);

            byte[] k1 = SecurityHelper.DeriveSymmetricKey(AlicePrivateKey, BobPublicKey);
            byte[] k2 = SecurityHelper.DeriveSymmetricKey(BobPrivateKey, AlicePublicKey);

            // Assert
            CollectionAssert.AreEqual(k1, k2);
        }

        [TestMethod]
        public void PKICryptoTest()
        {
            // Arrange
            string message_to_bob = "secret message";
            string reply_to_alice = "secret reply";
            byte[] BobPublicKey = null;
            byte[] AlicePublicKey = null;

            byte[] BobPrivateKey = SecurityHelper.GeneratePKIPair(out BobPublicKey);
            byte[] AlicePrivateKey = SecurityHelper.GeneratePKIPair(out AlicePublicKey);

            byte[] kA = SecurityHelper.DeriveSymmetricKey(AlicePrivateKey, BobPublicKey);
            byte[] kB = SecurityHelper.DeriveSymmetricKey(BobPrivateKey, AlicePublicKey);

            // Act
            byte[] msg1 = SecurityHelper.AEAD_Encrypt(kA, Encoding.UTF8.GetBytes(message_to_bob), SecurityHelper.AeCipher.Aes256CbcPkcs7);
            string incomming1 = Encoding.UTF8.GetString(SecurityHelper.AEAD_Decrypt(kB, msg1));

            byte[] msg2 = SecurityHelper.AEAD_Encrypt(kB, Encoding.UTF8.GetBytes(reply_to_alice), SecurityHelper.AeCipher.Aes256CbcPkcs7);
            string incomming2 = Encoding.UTF8.GetString(SecurityHelper.AEAD_Decrypt(kA, msg2));


            // Assert
            Assert.AreEqual(message_to_bob, incomming1);
            Assert.AreEqual(reply_to_alice, incomming2);

        }

        [TestMethod]
        public void DeriveSessionKey_HKDFTest()
        {
            // Arrange
            byte[] source_key = SecurityHelper.GetRandomKey(32);
            byte[] salt = SecurityHelper.GetRandomKey(16);
            byte[] context = "Test function".ToByte();
            byte[] context2 = "new context".ToByte();
            int sessionKeyLen = 57;
            int sessionKeyLen2 = 7389;

            // Act
            byte[] sessionkey = SecurityHelper.DeriveSessionKey_HKDF(source_key, context, sessionKeyLen, salt);
            byte[] sessionkey2 = SecurityHelper.DeriveSessionKey_HKDF(source_key, context, sessionKeyLen2, salt);
            byte[] sessionkey3 = SecurityHelper.DeriveSessionKey_HKDF(source_key, context, sessionKeyLen2, salt);
            byte[] sessionkey4 = SecurityHelper.DeriveSessionKey_HKDF(source_key, context2, sessionKeyLen2, salt);

            // Assert
            Assert.IsTrue(sessionkey.Length == sessionKeyLen);
            Assert.IsTrue(sessionkey2.Length == sessionKeyLen2);
            CollectionAssert.AreEqual(sessionkey2, sessionkey3);
            CollectionAssert.AreNotEquivalent(sessionkey3, sessionkey4);
        }

    }
}
