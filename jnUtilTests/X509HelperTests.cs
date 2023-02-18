using jnUtil;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
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

            X509Certificate2 end = new X509Certificate2(certs[^1]);
            X509Certificate2 nextToEnd = new X509Certificate2(certs[^2]);
            
            // Assert
            Assert.AreEqual(ChainLength, certs.Length);
            Assert.AreEqual(end.Issuer, nextToEnd.Subject);
        }
    }
}
