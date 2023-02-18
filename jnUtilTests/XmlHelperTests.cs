using jnUtil;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Security;
using System.Text;
using System.Xml;

namespace jnUtilTests
{
    [TestClass]
    public class XmlHelperTests
    {
        [TestMethod]
        public void EncrypttionDecryptionTests()
        {
            // Arrange
            XmlDocument doc = GetTestDocument("header","content");
            SecureString pass = "password".ToSecureString();

            // Act
            XMLhelper.EncryptSimplified(doc, "content", pass, null);
            XMLhelper.DecryptSimplified(doc, pass, null);
            string content = doc.GetInnerTextFromChild("content");

            // Assert
            Assert.AreEqual("content", content, "String to bytes and back failed");
        }

        private XmlDocument GetTestDocument(string headertext = "this is the header", string contenttext = "this is the content")
        {
            XmlDocument doc = new XmlDocument();
            XmlElement message = doc.CreateElement("message");

            XmlElement header = doc.CreateElement("header");
            header.InnerText = headertext;

            XmlElement content = doc.CreateElement("content");
            content.InnerText = contenttext;

            message.AppendChild(header);
            message.AppendChild(content);
            doc.AppendChild(message);


            return doc;
        }


    }
}
