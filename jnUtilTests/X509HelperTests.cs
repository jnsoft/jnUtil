using jnUtil;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace jnUtilTests
{
    [TestClass]
    public class X509HelperTests
    {
        [TestMethod]
        public void TestExportImportPfx()
        {
            // Arrange
            X509Certificate2 CAcert = X509Helper.CreateCACert("UnitTestingCA", null);

            // Act
            // byte[] pfx = X509Helper.SaveX509CertToPfx()


            // Assert

        }

        [TestMethod]
        public void TestCreateCertChain()
        {
            // Arrange
            X509Certificate2 CAcert = X509Helper.CreateCACert("UnitTestingCA", null);
            int ChainLength = 5;

            // Act
            byte[][] certs = X509Helper.CreateCertChain(CAcert, "Root CA", ChainLength, null);

            X509Certificate2 end = X509CertificateLoader.LoadPkcs12(certs[^1], password: null);
            X509Certificate2 nextToEnd = X509CertificateLoader.LoadPkcs12(certs[^2], password: null);


            // Assert
            Assert.AreEqual(ChainLength, certs.Length);
            Assert.AreEqual(end.Issuer, nextToEnd.Subject);
        }

        [TestMethod]
        public void ExportCertificatePublicKey_ShouldReturnCertWithoutPrivateKey()
        {
            // Arrange
            X509Certificate2 certWithKey = X509Helper.CreateCACert("UnitTestingCA", null);
            Assert.IsTrue(certWithKey.HasPrivateKey, "Source cert should have a private key");

            // Act
            X509Certificate2 publicOnly = X509Helper.ExportCertificatePublicKey(certWithKey);

            // Assert
            Assert.IsNotNull(publicOnly);
            Assert.IsFalse(publicOnly.HasPrivateKey, "Exported public cert should NOT have a private key");
            Assert.AreEqual(certWithKey.Subject, publicOnly.Subject);
            Assert.AreEqual(certWithKey.Thumbprint, publicOnly.Thumbprint);
            Assert.AreEqual(certWithKey.NotBefore, publicOnly.NotBefore);
            Assert.AreEqual(certWithKey.NotAfter, publicOnly.NotAfter);
            Assert.AreEqual(certWithKey.SerialNumber, publicOnly.SerialNumber);
        }

        [TestMethod]
        public void ExportCertificatePublicKey_IsCA_ShouldRemainTrue()
        {
            // Arrange
            X509Certificate2 caCert = X509Helper.CreateCACert("UnitTestingCA", null);

            // Act
            X509Certificate2 publicOnly = X509Helper.ExportCertificatePublicKey(caCert);

            // Assert
            Assert.IsTrue(publicOnly.IsCA(), "Exported public cert should still be identified as a CA cert");
        }

        [TestMethod]
        public void ExportCertificatePublicKey_RawDataMatchesGetPublicKey()
        {
            // Arrange
            X509Certificate2 cert = X509Helper.CreateCACert("UnitTestingCA", null);

            // Act
            byte[] rawFromHelper = X509Helper.GetPublicKey(cert);
            X509Certificate2 exported = X509Helper.ExportCertificatePublicKey(cert);

            // Assert
            CollectionAssert.AreEqual(rawFromHelper, exported.RawData,
                "RawData of the exported cert should match the bytes returned by GetPublicKey");
        }

        [TestMethod]
        public void ExportCertificatePublicKey_SignedCert_PreservesIssuerChain()
        {
            // Arrange
            X509Certificate2 caCert = X509Helper.CreateCACert("UnitTestingCA", null);
            X509Certificate2 leafCert = X509Helper.CreateAndSignCertificate("localhost", caCert);

            // Act
            X509Certificate2 publicOnly = X509Helper.ExportCertificatePublicKey(leafCert);

            // Assert
            Assert.IsFalse(publicOnly.HasPrivateKey);
            Assert.AreEqual(leafCert.Issuer, publicOnly.Issuer);
            Assert.AreEqual(caCert.Subject, publicOnly.Issuer);
        }

        [TestMethod]
        public void X509FromPfx_WithoutPassword_LoadsCertWithPrivateKey()
        {
            // Arrange
            X509Certificate2 original = X509Helper.CreateCACert("UnitTestingCA", null);
            byte[] pfx = X509Helper.X509ToPfx(original, null);

            // Act
            X509Certificate2 loaded = X509Helper.X509FromPfx(pfx, null);

            // Assert
            Assert.IsNotNull(loaded);
            Assert.IsTrue(loaded.HasPrivateKey, "Loaded cert should have a private key");
            Assert.AreEqual(original.Subject, loaded.Subject);
            Assert.AreEqual(original.Thumbprint, loaded.Thumbprint);
            Assert.AreEqual(original.SerialNumber, loaded.SerialNumber);
        }

        [TestMethod]
        public void X509FromPfx_WithPassword_LoadsCertWithPrivateKey()
        {
            // Arrange
            X509Certificate2 original = X509Helper.CreateCACert("UnitTestingCA", null);
            SecureString password = "TestPassword123!".ToSecureString();
            byte[] pfx = X509Helper.X509ToPfx(original, password);

            // Act
            X509Certificate2 loaded = X509Helper.X509FromPfx(pfx, password);

            // Assert
            Assert.IsNotNull(loaded);
            Assert.IsTrue(loaded.HasPrivateKey, "Loaded cert should have a private key");
            Assert.AreEqual(original.Subject, loaded.Subject);
            Assert.AreEqual(original.Thumbprint, loaded.Thumbprint);
            Assert.AreEqual(original.SerialNumber, loaded.SerialNumber);
        }

        [TestMethod]
        public void X509FromPfx_WithWrongPassword_ThrowsException()
        {
            // Arrange
            X509Certificate2 original = X509Helper.CreateCACert("UnitTestingCA", null);
            SecureString correctPassword = "CorrectPassword123!".ToSecureString();
            SecureString wrongPassword = "WrongPassword456!".ToSecureString();
            byte[] pfx = X509Helper.X509ToPfx(original, correctPassword);

            // Act & Assert
            try
            {
                X509Helper.X509FromPfx(pfx, wrongPassword);
                Assert.Fail("Expected CryptographicException was not thrown");
            }
            catch (CryptographicException)
            {
                // expected
            }
        }

        [TestMethod]
        public void X509FromPfx_PrivateKeyIsExportable()
        {
            // Arrange
            X509Certificate2 original = X509Helper.CreateCACert("UnitTestingCA", null);
            SecureString password = "TestPassword123!".ToSecureString();
            byte[] pfx = X509Helper.X509ToPfx(original, password);

            // Act
            X509Certificate2 loaded = X509Helper.X509FromPfx(pfx, password);

            // Assert — re-exporting should succeed if Exportable flag was honoured
            byte[] reExported = X509Helper.X509ToPfx(loaded, password);
            Assert.IsNotNull(reExported);
            Assert.IsNotEmpty(reExported, "Re-exported PFX should not be empty");
        }
    }

}


    
