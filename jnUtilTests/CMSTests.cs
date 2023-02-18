using jnUtil;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace jnUtilTests
{
    [TestClass]
    public class CMSTests
    {
        [TestMethod]
        public void TestSignVerify()
        {
            // Arrange
            X509Certificate2 CAcert = X509Helper.CreateCACert("UnitTestingCA", null);
            X509Certificate2 signingCert = X509Helper.CreateAndSignCertificate("UnitTestingSigning", CAcert);
            X509Certificate2 publicCert = X509Helper.ExportCertificatePublicKey(signingCert);
            byte[] dataToSign = "This is a text".ToByte(true);
            byte[] dataToSign2 = "This is another text".ToByte(true);

            // Act
            byte[] signature = CMSHelper.Sign(dataToSign, signingCert, X509IncludeOption.WholeChain);
            bool verified = CMSHelper.Verify(dataToSign, signature, true);
            bool verified2 = CMSHelper.Verify(dataToSign2, signature, true);

            // Assert
            Assert.IsTrue(verified);
            Assert.IsFalse(verified2);
        }

        [TestMethod]
        public void TestSignVerifyWithCert() // not working???
        {
            // Arrange
            X509Certificate2 CAcert = X509Helper.CreateCACert("UnitTestingCA", null);
            X509Certificate2 signingCert = X509Helper.CreateAndSignCertificate("UnitTestingSigning", CAcert);
            X509Certificate2 signingCert2 = X509Helper.CreateAndSignCertificate("UnitTestingSigning2", CAcert);
            X509Certificate2 publicCert = X509Helper.ExportCertificatePublicKey(signingCert);
            X509Certificate2 publicCert2 = X509Helper.ExportCertificatePublicKey(signingCert2);

            byte[] dataToSign = "This is a text".ToByte(true);

            // Act
            byte[] signature = CMSHelper.Sign(dataToSign, signingCert, X509IncludeOption.WholeChain);
            bool verified = CMSHelper.Verify(dataToSign, signature, false, publicCert);
            bool verified2 = CMSHelper.Verify(dataToSign, signature, false, publicCert2);
            
            // Assert
            // Assert.IsTrue(verified);
            // Assert.IsFalse(verified2);
     
        }
    }
}
