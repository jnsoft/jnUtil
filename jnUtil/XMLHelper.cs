using jnUtil.Properties;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.Xml.Schema;
using System.Xml.Xsl;

namespace jnUtil
{
    public static class XMLhelper
    {
        #region Working with XML

        public static string GetInnerTextFromChild(this XmlNode node, string childname)
        {
            if (node.HasChildNodes)
                return GetInnerTextFromNode(node.ChildNodes, childname, true);
            return string.Empty;
        }

        // usage: string s = GetInnerTextFromNode(xmlDoc.ChildNodes, "Signature", false);
        public static string GetInnerTextFromNode(XmlNodeList list, string nodeName, bool deep, bool ignoreNameSpace = false)
        {
            XmlNode n = FindNodeByName(list, nodeName, deep, ignoreNameSpace);
            if (n != null && !string.IsNullOrWhiteSpace(n.InnerText))
                return n.InnerText;
            else return string.Empty;
        }

        // find all contents found inside specific elements
        public static List<string> GetAllInnerTexts(XmlDocument doc, string elementname)
        {
            List<string> res = new List<string>();
            res.Clear();
            XmlReader rdr = XmlReader.Create(new System.IO.StringReader(doc.DocumentElement.OuterXml));
            while (rdr.Read())
            {
                if (rdr.NodeType == XmlNodeType.Element)
                {
                    if (!rdr.IsEmptyElement && rdr.Name == elementname)
                    {
                        res.Add(rdr.ReadElementContentAsString());
                    }
                }
            }
            return res;
        }

        // usage: string s = GetAttribute(xmlDoc.ChildNodes,"header" "Id");
        public static string GetAttribute(this XmlNodeList list, string nodeName, string attribute, bool deep) => 
            FindNodeByName(list, nodeName, deep).GetAttribute(attribute);

        public static string GetAttribute(this XmlNode node, string attribute)
        {
            if (node.Attributes.Count != 0)
                return ((XmlElement)node).GetAttribute(attribute);
            else
                return string.Empty;
        }

        // usage: XmlNode sign = FindNodeByName(xmlDoc.ChildNodes, "Signature");
        public static XmlNode FindNodeByName(this XmlNodeList list, string nodeName, bool deep, bool ignoreNameSpace = false)
        {
            if (ignoreNameSpace)
                nodeName = nodeName.Substring(nodeName.IndexOf(':') + 1, nodeName.Length - nodeName.IndexOf(':') - 1);
            nodeName = nodeName.ToLower();
            if (list.Count > 0)
            {
                foreach (XmlNode node in list)
                {
                    if (!ignoreNameSpace ? node.Name.ToLower().Equals(nodeName) : node.Name.Substring(node.Name.IndexOf(':') + 1, node.Name.Length - node.Name.IndexOf(':') - 1).ToLower().Equals(nodeName))
                        return node;
                    if (deep && node.HasChildNodes)
                    {
                        XmlNode nodeFound = FindNodeByName(node.ChildNodes, nodeName, deep, ignoreNameSpace);
                        if (nodeFound != null)
                            return nodeFound;
                    }
                }
            }
            return null;
        }

        public static List<XmlNode> FindAllNodesByName(this XmlNodeList list, string nodeName, bool deep, bool ignoreNameSpace = false)
        {
            List<XmlNode> nodes = new List<XmlNode>();
            nodeName = nodeName.ToLower();
            if (ignoreNameSpace)
                nodeName = nodeName.Substring(nodeName.IndexOf(':') + 1, nodeName.Length - nodeName.IndexOf(':') - 1);

            if (list.Count > 0)
            {
                foreach (XmlNode node in list)
                {
                    if (!ignoreNameSpace ? node.Name.ToLower().Equals(nodeName) : node.Name.Substring(node.Name.IndexOf(':') + 1, node.Name.Length - node.Name.IndexOf(':') - 1).ToLower().Equals(nodeName))
                        nodes.Add(node);

                    if (deep && node.HasChildNodes)
                    {
                        List<XmlNode> nodesFound = FindAllNodesByName(node.ChildNodes, nodeName, deep, ignoreNameSpace);
                        if (nodesFound != null && nodesFound.Count > 0)
                            nodes.AddRange(nodesFound);
                    }
                }
            }
            return nodes;
        }

        public static XmlNode GetNode(this XmlNode node, string nodeName, bool deep)
        {
            if (node.Name.Equals(nodeName))
                return node;
            else if (node.HasChildNodes)
            {
                XmlNode nodeFound = FindNodeByName(node.ChildNodes, nodeName, deep);
                if (nodeFound != null)
                    return nodeFound;
            }

            return null;
        }

        public static XmlNode GetNode(this XmlNodeList list, string nodeName, bool deep)
        {
            if (list.Count > 0)
            {
                foreach (XmlNode node in list)
                {
                    if (node.Name.Equals(nodeName)) return node;
                    if (node.HasChildNodes)
                    {
                        XmlNode nodeFound = FindNodeByName(node.ChildNodes, nodeName, deep);
                        if (nodeFound != null)
                            return nodeFound;
                    }
                }
            }
            return null;
        }

        public static XmlNodeList GetNodeList(this XmlDocument doc, string elementname, string ns = "")
        {
            if (string.IsNullOrWhiteSpace(ns))
                return doc.GetElementsByTagName(elementname);
            return doc.GetElementsByTagName(elementname, ns);
        }

        public static bool InsertNode(this XmlDocument doc, XmlNode node, string outernode)
        {
            bool success = false;
            try
            {
                XmlNode newNode = doc.ImportNode(node, true);
                XmlNode parent = doc.GetNode(outernode, true);
                parent.AppendChild(newNode);
                success = true;
            }
            catch (Exception e)
            {
                throw e;
            }

            return success;
        }

        public static bool InsertNodeAfter(this XmlDocument doc, XmlNode node, string lastNodeBefore)
        {
            bool success = false;
            try
            {
                XmlNode newNode = doc.ImportNode(node, true);
                XmlNode last = doc.GetNode(lastNodeBefore, true);
                doc.DocumentElement.InsertAfter(newNode, last);
                success = true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return success;
        }

        public static bool InsertNodeBefore(this XmlDocument doc, XmlNode node, string firstNodeAfter)
        {
            bool success = false;
            try
            {
                XmlNode newNode = doc.ImportNode(node, true);
                XmlNode first = doc.DocumentElement.GetNode(firstNodeAfter, true);
                doc.InsertBefore(newNode, first);
                success = true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return success;
        }

        // standalone: only relvant if doc uses DTD (not xsd schema). If an external DTD contains default values or entity declarations, then standalone=no, else yes (yes = DTD only for validation).
        public static void AddXmlDeclaration(ref XmlDocument doc, string version = "1.0", string encoding = "UTF-8", string standalone = "yes")
        {
            XmlDeclaration dec;
            dec = doc.CreateXmlDeclaration(version, encoding, standalone);
            XmlElement root = doc.DocumentElement;
            doc.InsertBefore(dec, root);
        }


        #endregion

        #region Files and pretty print

        public static XmlDocument XmlFromFile(string filename)
        {
            if (File.Exists(filename))
            {
                XmlDocument doc = new XmlDocument();
                doc.PreserveWhitespace = false;
                using (XmlTextReader tr = new XmlTextReader(filename))
                {
                    doc.Load(tr);
                }
                return doc;
            }
            else
                return null;
        }

        // standalone: only relvant if doc uses DTD (not xsd schema). If an external DTD contains default values or entity declarations, then standalone=no, else yes (yes = DTD only for validation).
        static public void XmlToFile(XmlElement xml, string filename, bool isFormated = true, bool isStandAlone = false)
        {
            if (xml.FirstChild is XmlDeclaration)
            {
                xml.RemoveChild(xml.FirstChild);
            }


            if (!isFormated)
            {
                // Save the XML document to a file specified 
                using (XmlTextWriter xmltw = new XmlTextWriter(filename, new UTF8Encoding(true)))
                {
                    if (isStandAlone)
                        xmltw.WriteStartDocument(true);
                    else
                        xmltw.WriteStartDocument();
                    xml.WriteTo(xmltw);
                }
            }
            else
            {
                XmlWriterSettings settings = new XmlWriterSettings
                {
                    Indent = true,
                    IndentChars = @"    ",
                    NewLineChars = Environment.NewLine,
                    NewLineHandling = NewLineHandling.Replace,
                    Encoding = Encoding.UTF8
                };

                //XmlWriter writer = XmlWriter.Create(xmltw,settings); // not used
                using (XmlWriter objXmlWriter = XmlWriter.Create(filename, settings))
                {
                    // Write xml declaration
                    if (isStandAlone)
                        objXmlWriter.WriteStartDocument(true);
                    else
                        objXmlWriter.WriteStartDocument();
                    xml.WriteTo(objXmlWriter);
                    objXmlWriter.Close();
                }

                //using (XmlTextWriter xmltw = new XmlTextWriter(filename, new UTF8Encoding(true)))
                //{
                //    if (isStandAlone)
                //        xmltw.WriteStartDocument(true);
                //    else
                //        xmltw.WriteStartDocument();
                //    xml.WriteTo(xmltw);
                //}
            }
        }

        static public XmlDocument XmlFromCSV(string csv, char delimeter, bool headerIncluded = true, string documentName = "Document", string itemName = "item", bool includeEmptyelements = false, string ns = "", string nsVersion = "")
        {
            try
            {
                string[] lines = csv.SplitToLines();
                string[] headers = { };
                if (headerIncluded)
                    headers = lines[0].Split(delimeter).Select(x => x.Trim('\"')).ToArray();

                int rows = lines.Count();

                XmlDocument doc = new XmlDocument();

                XmlElement mainEl = doc.CreateElement(documentName, ns);
                if (!string.IsNullOrWhiteSpace(nsVersion))
                    mainEl.SetAttribute("version", nsVersion);

                for (int i = headerIncluded ? 1 : 0; i < rows; i++)
                {
                    XmlElement item = doc.CreateElement(itemName, ns);
                    for (int j = 0; j < headers.Count(); j++)
                    {
                        string text = lines[i].Split(delimeter).Select(x => x.Trim('\"')).ToArray()[j].ToString();
                        if (!string.IsNullOrWhiteSpace(text) || includeEmptyelements)
                        {
                            XmlElement el = doc.CreateElement(headers[j].Clean(true).Replace(' ', '_'), ns);
                            el.InnerText = lines[i].Split(delimeter).Select(x => x.Trim('\"')).ToArray()[j];
                            item.AppendChild(el);
                        }
                    }
                    mainEl.AppendChild(item);
                }
                doc.AppendChild(mainEl);
                return doc;

                //var xml = new XElement("TopElement", lines.Where((line, index) => index > 0).Select(line => new XElement("Item", line.Split(',').Select((column, index) => new XElement(headers[index], column)))));
            }
            catch (Exception e)
            {
                throw e;
                //return false;
            }
        }

        static public bool ToCSV(this XmlDocument doc, string outputPath)
        {
            try
            {
                string stylesheet = Resources.XSLT_ToCsv;
                   
                XmlToFile(doc.DocumentElement, outputPath + ".tmp", false);

                XmlReader xr = XmlReader.Create(StreamHelper.StringToStream(stylesheet));

                XsltTransform(xr, outputPath + ".tmp", outputPath, true);

               
                return true;
            }
            catch (Exception e)
            {
                throw e;
            }
        }
        
        static public string Beautify(this XmlDocument doc, bool forceUTF8 = false)
        {
            StringBuilder sb = new StringBuilder();
            XmlWriterSettings settings = new XmlWriterSettings
            {
                Indent = true,
                IndentChars = @"    ",
                NewLineChars = Environment.NewLine,
                NewLineHandling = NewLineHandling.Replace,
                Encoding = Encoding.UTF8
            };

            using (XmlWriter writer = XmlWriter.Create(sb, settings))
            {
                if (doc.ChildNodes[0] is XmlProcessingInstruction)
                    doc.RemoveChild(doc.ChildNodes[0]);
                doc.Save(writer);
            }

            if (forceUTF8) // strings use UTF16 by default in .NET, cannot be overwritten in string writing by choosing encoder...
                sb.Replace(Encoding.Unicode.WebName, Encoding.UTF8.WebName, 0, 56);
            return sb.ToString();
        }

        // repalces charachters so that html rendering of tags is possible
        static public string ToHtmlViewable(this XmlDocument doc, bool forceUTF8 = false)
        {
            string output = Beautify(doc, forceUTF8);

            return output.Replace("<", "&lt;").Replace(">", "&gt;").Replace(" ", "&nbsp;").Replace(Environment.NewLine, "<br />");


            // Regex Spaces = new Regex(@"\s+", RegexOptions.Compiled);
            // output = Regex.Replace(output, @"[^a-zåäöA-ZÅÄÖ0-9]", ""); // only preserve listed chars
        }

        #endregion

        #region Misc

        public static XmlDocument Clone(this XmlDocument doc) => (XmlDocument)doc.CloneNode(true);

        #endregion

        #region Binary files and Base64

        public static byte[] ReadBinaryFromXmlNode(XmlNode node) => node.InnerText.FromBase64();

        // usage: XmlNode file = doc.ImportNode(BinaryAsBase64Doc(binary); 
        //        element.AppendChild(xmlNode);
        public static XmlDocument BinaryAsBase64Doc(byte[] binary, string ElementName = "base64data", string NameSpace = "")
        {
            XmlDocument doc = new XmlDocument();

            string ns = null;
            if (!string.IsNullOrWhiteSpace(NameSpace))
                ns = NameSpace;

            XmlNode n = doc.CreateElement(ElementName, NameSpace);
            BinaryAsBase64Node(ref n, binary);
            doc.AppendChild(n);
            return doc;
        }

        // common to add base64 data as "CDATA"
        public static void AddBinaryToXmlNode(XmlNode node, byte[] binary, string ChildElementName, string NameSpace = "")
        {
            string ns = null;
            if (!string.IsNullOrWhiteSpace(NameSpace))
                ns = NameSpace;

            //XmlNode file = el.OwnerDocument.ImportNode(BinaryAsBase64Doc(s).DocumentElement, true);

            if (string.IsNullOrWhiteSpace(ChildElementName))
            {
                BinaryAsBase64Node(ref node, binary);
            }
            else
            {
                XmlNode n2 = node.OwnerDocument.CreateElement(ChildElementName, NameSpace);
                BinaryAsBase64Node(ref n2, binary);
                node.AppendChild(n2);
            }

        }

        private static void BinaryAsBase64Node(ref XmlNode n, byte[] binary) => n.AppendChild(n.OwnerDocument.CreateTextNode(binary.ToBase64()));

        #endregion

        #region Xsd Schema validation and xslt transforms

        public static string XlstTransform(this XmlDocument doc, string stylesheet, bool trustedSource = false)
        {
            XslCompiledTransform xslt = new XslCompiledTransform();
            XmlReader xr = XmlReader.Create(StreamHelper.StringToStream(stylesheet));
            if (trustedSource)
                xslt.Load(xr, XsltSettings.TrustedXslt, new XmlUrlResolver());
            else
            {
                System.Security.PermissionSet ps = new System.Security.PermissionSet(System.Security.Permissions.PermissionState.None);
                //XmlResolver secureResolver = new XmlSecureResolver(new XmlUrlResolver(), ps);
                xslt.Load(xr, XsltSettings.Default, new XmlUrlResolver());
            }

            XmlReader xmlReader = new XmlNodeReader(doc);
            //XmlDocument transformedDoc = new XmlDocument();
            XmlWriterSettings ws = new XmlWriterSettings();
            ws.ConformanceLevel = ConformanceLevel.Auto;
            using (var sw = new StringWriter())
            {
                using (var xw = XmlWriter.Create(sw, ws))
                {
                    xslt.Transform(doc, xw);
                }
                return sw.ToString();
            }
        }

        public static void XsltTransform(string stylesheetURI, string inputURI, string outputFile, bool trustedSource = false)
        {
            try
            {
                XslCompiledTransform xslt = new XslCompiledTransform();
                if (trustedSource)
                    xslt.Load(stylesheetURI, XsltSettings.TrustedXslt, new XmlUrlResolver());
                else
                {
                    XmlResolver secureResolver = new XmlSecureResolver(new XmlUrlResolver(), inputURI);
                    xslt.Load(stylesheetURI, XsltSettings.Default, secureResolver);
                }

                xslt.Transform(inputURI, outputFile);
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        public static void XsltTransform(XmlReader stylesheet, string inputURI, string outputFile, bool trustedSource = false)
        {
            try
            {
                XslCompiledTransform xslt = new XslCompiledTransform();
                if (trustedSource)
                    xslt.Load(stylesheet, XsltSettings.TrustedXslt, new XmlUrlResolver());
                else
                {
                    XmlResolver secureResolver = new XmlSecureResolver(new XmlUrlResolver(), inputURI);
                    xslt.Load(stylesheet, XsltSettings.Default, secureResolver);
                }
                xslt.Transform(inputURI, outputFile);
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        public static bool DtdValidate(string xmlFile)
        {
            XmlTextReader r = new XmlTextReader(xmlFile);
            XmlValidatingReader v = new XmlValidatingReader(r);
            v.ValidationType = ValidationType.DTD;
            bool isValid = true;
            v.ValidationEventHandler += new ValidationEventHandler(ValidationCallBack);
            while (v.Read())
            {
                // Can add code here to process the content.
            }
            v.Close();
            return isValid;
        }

        public static bool XsdValidate(string xmlFile, out string[] errorMessages, string schemaFile = "")
        {
            List<string> errors = new List<string>();
            // Set the validation settings.
            XmlReaderSettings settings = new XmlReaderSettings();
            settings.ValidationType = ValidationType.Schema;
            settings.ValidationFlags |= XmlSchemaValidationFlags.ProcessInlineSchema;
            settings.ValidationFlags |= XmlSchemaValidationFlags.ProcessSchemaLocation;
            settings.ValidationFlags |= XmlSchemaValidationFlags.ReportValidationWarnings;
            //settings.ValidationEventHandler += new ValidationEventHandler(ValidationCallBack);
            settings.ValidationEventHandler += (o, e) => errors.Add(e.Severity == XmlSeverityType.Warning ? string.Format("Warning: Matching schema not found, no validation occurred. {0}", e.Message) : string.Format("Validation error (line {0}, position {1}): {2})", e.Exception.LineNumber, e.Exception.LinePosition, e.Message));

            if (!string.IsNullOrWhiteSpace(schemaFile))
            {
                string targetNamespace;
                try
                {
                    targetNamespace = XmlFromFile(schemaFile).DocumentElement.GetAttribute("targetNamespace");
                }
                catch
                {
                    targetNamespace = "";
                }
                settings.Schemas.Add(targetNamespace, schemaFile);
            }

            // Create the XmlReader object.
            XmlReader reader = XmlReader.Create(xmlFile, settings);

            // Parse the file. 
            while (reader.Read())
            {
                // Can add code here to process the content.
            }
            reader.Close();
            errorMessages = errors.ToArray<string>();
            return errorMessages.Length == 0;
        }

        // Display any warnings or errors.
        private static void ValidationCallBack(object sender, ValidationEventArgs args)
        {
            if (args.Severity == XmlSeverityType.Warning)
                Console.WriteLine("\tWarning: Matching schema not found.  No validation occurred." + args.Message);
            else
                Console.WriteLine(string.Format("Validation error (line {0}, position {1}): {2}", args.Exception.LineNumber, args.Exception.LinePosition, args.Message));
        }

        #endregion

        #region Encryption / Decryption

        public static void EncryptSimplified(this XmlDocument doc, string ElementToEncrypt, SecureString password, byte[] passwordSalt) => 
            doc.EncryptElement(ElementToEncrypt, SecurityHelper.getAES(SecurityHelper.AesModes.Aes256CbcPkcs7, SecurityHelper.GetKeyFromPassword(password, passwordSalt, SecurityHelper.KEYSIZE / 8)), "AES 256");

        public static void DecryptSimplified(this XmlDocument doc, SecureString password, byte[] passwordSalt) => 
            doc.Decrypt(SecurityHelper.getAES(SecurityHelper.AesModes.Aes256CbcPkcs7, SecurityHelper.GetKeyFromPassword(password, passwordSalt, SecurityHelper.KEYSIZE / 8)), "AES 256");

        public static void EncryptElement(this XmlDocument Doc, string ElementToEncrypt, RSA Alg, string KeyName)
        {
            // Check the arguments.   
            if (Doc == null)
                throw new ArgumentNullException("Doc");
            if (ElementToEncrypt == null)
                throw new ArgumentNullException("ElementToEncrypt");
            if (Alg == null)
                throw new ArgumentNullException("Alg");

            //////////////////////////////////////////////// 
            // Find the specified element in the XmlDocument 
            // object and create a new XmlElemnt object. 
            ////////////////////////////////////////////////

            XmlElement elementToEncrypt = Doc.GetElementsByTagName(ElementToEncrypt)[0] as XmlElement;

            // Throw an XmlException if the element was not found. 
            if (elementToEncrypt == null)
            {
                throw new XmlException("The specified element was not found");

            }

            ////////////////////////////////////////////////// 
            // Create a new instance of the EncryptedXml class  
            // and use it to encrypt the XmlElement with the  
            // a new random symmetric key. 
            ////////////////////////////////////////////////// 

            // Create a 256 bit Rijndael key.
            RijndaelManaged sessionKey = new RijndaelManaged();
            sessionKey.KeySize = 256;

            EncryptedXml eXml = new EncryptedXml();

            byte[] encryptedElement = eXml.EncryptData(elementToEncrypt, sessionKey, false);

            //////////////////////////////////////////////// 
            // Construct an EncryptedData object and populate 
            // it with the desired encryption information. 
            ////////////////////////////////////////////////


            EncryptedData edElement = new EncryptedData();
            edElement.Type = EncryptedXml.XmlEncElementUrl;

            // Create an EncryptionMethod element so that the  
            // receiver knows which algorithm to use for decryption.

            edElement.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);

            // Encrypt the session key and add it to an EncryptedKey element.
            EncryptedKey ek = new EncryptedKey();

            byte[] encryptedKey = EncryptedXml.EncryptKey(sessionKey.Key, Alg, false);

            ek.CipherData = new CipherData(encryptedKey);

            ek.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url);

            // Set the KeyInfo element to specify the 
            // name of the RSA key. 

            // Create a new KeyInfo element.
            edElement.KeyInfo = new KeyInfo();

            // Create a new KeyInfoName element.
            KeyInfoName kin = new KeyInfoName();

            // Specify a name for the key.
            kin.Value = KeyName;

            // Add the KeyInfoName element to the  
            // EncryptedKey object.
            ek.KeyInfo.AddClause(kin);

            // Add the encrypted key to the  
            // EncryptedData object.

            edElement.KeyInfo.AddClause(new KeyInfoEncryptedKey(ek));

            // Add the encrypted element data to the  
            // EncryptedData object.
            edElement.CipherData.CipherValue = encryptedElement;

            //////////////////////////////////////////////////// 
            // Replace the element from the original XmlDocument 
            // object with the EncryptedData element. 
            ////////////////////////////////////////////////////

            EncryptedXml.ReplaceElement(elementToEncrypt, edElement, false);

        }

        private static void EncryptElement(this XmlDocument Doc, string ElementToEncrypt, SymmetricAlgorithm Alg, string KeyName)
        {
            // Check the arguments.   
            if (Doc == null)
                throw new ArgumentNullException("Doc");
            if (ElementToEncrypt == null)
                throw new ArgumentNullException("ElementToEncrypt");
            if (Alg == null)
                throw new ArgumentNullException("Alg");

            // Find the specified element in the XmlDocument object and create a new XmlElemnt object. 
            XmlElement elementToEncrypt = Doc.GetElementsByTagName(ElementToEncrypt)[0] as XmlElement;

            if (elementToEncrypt == null)
                throw new XmlException("The specified element was not found");

            // Create a new instance of the EncryptedXml class and use it to encrypt the XmlElement with the symmetric key. 
            EncryptedXml eXml = new EncryptedXml();

            byte[] encryptedElement = eXml.EncryptData(elementToEncrypt, Alg, false);

            // Construct an EncryptedData object and populate it with the desired encryption information. 
            EncryptedData edElement = new EncryptedData();

            edElement.Type = EncryptedXml.XmlEncElementUrl;

            // Create an EncryptionMethod element so that the receiver knows which algorithm to use for decryption. 
            // Determine what kind of algorithm is being used and supply the appropriate URL to the EncryptionMethod element. 
            string encryptionMethod = null;

            if (Alg is TripleDES)
                encryptionMethod = EncryptedXml.XmlEncTripleDESUrl;
            else if (Alg is DES)
                encryptionMethod = EncryptedXml.XmlEncDESUrl;
            else if (Alg is Rijndael)
            {
                switch (Alg.KeySize)
                {
                    case 128:
                        encryptionMethod = EncryptedXml.XmlEncAES128Url;
                        break;
                    case 192:
                        encryptionMethod = EncryptedXml.XmlEncAES192Url;
                        break;
                    case 256:
                        encryptionMethod = EncryptedXml.XmlEncAES256Url;
                        break;
                }
            }
            else if (Alg is Aes)
            {
                switch (Alg.KeySize)
                {
                    case 128:
                        encryptionMethod = EncryptedXml.XmlEncAES128Url;
                        break;
                    case 192:
                        encryptionMethod = EncryptedXml.XmlEncAES192Url;
                        break;
                    case 256:
                        encryptionMethod = EncryptedXml.XmlEncAES256Url;
                        break;
                }
            }

            else // Throw an exception if the transform is not in the previous categories 
                throw new CryptographicException("The specified algorithm is not supported for XML Encryption.");

            edElement.EncryptionMethod = new EncryptionMethod(encryptionMethod);

            // Set the KeyInfo element to specify the name of a key. 
            edElement.KeyInfo = new KeyInfo();

            // Create a new KeyInfoName element and specify a name for the key
            KeyInfoName kin = new KeyInfoName();
            kin.Value = KeyName;

            // Add the KeyInfoName element.
            edElement.KeyInfo.AddClause(kin);

            // Add the encrypted element data to the EncryptedData object.
            edElement.CipherData.CipherValue = encryptedElement;

            // Replace the element from the original XmlDocument object with the EncryptedData element. 
            EncryptedXml.ReplaceElement(elementToEncrypt, edElement, false);
        }

        public static void Decrypt(this XmlDocument Doc, RSA Alg, string KeyName)
        {
            // Check the arguments.   
            if (Doc == null)
                throw new ArgumentNullException("Doc");
            if (Alg == null)
                throw new ArgumentNullException("Alg");
            if (KeyName == null)
                throw new ArgumentNullException("KeyName");

            // Create a new EncryptedXml object.
            EncryptedXml exml = new EncryptedXml(Doc);

            // Add a key-name mapping. 
            // This method can only decrypt documents 
            // that present the specified key name.
            exml.AddKeyNameMapping(KeyName, Alg);

            // Decrypt the element.
            exml.DecryptDocument();

        }

        public static void Decrypt(this XmlDocument Doc, SymmetricAlgorithm Alg, string KeyName)
        {
            // Check the arguments.   
            if (Doc == null)
                throw new ArgumentNullException("Doc");
            if (Alg == null)
                throw new ArgumentNullException("Alg");
            if (KeyName == null)
                throw new ArgumentNullException("KeyName");

            // Create a new EncryptedXml object.
            EncryptedXml exml = new EncryptedXml(Doc);

            // Add a key-name mapping. 
            // This method can only decrypt documents 
            // that present the specified key name.
            exml.AddKeyNameMapping(KeyName, Alg);

            // Decrypt the element.
            exml.DecryptDocument();

        }

        #endregion

        #region X509

        public static bool VerifyX509Signature(XmlDocument doc)
        {
            SignedXml signedXml = new SignedXml(doc);
            XmlNode MessageSignatureNode = doc.GetElementsByTagName("Signature")[0];
            signedXml.LoadXml((XmlElement)MessageSignatureNode);

            // get cert from signature
            X509Certificate2 certificate = null;
            foreach (KeyInfoClause clause in signedXml.KeyInfo)
            {
                if (clause is KeyInfoX509Data)
                {
                    if (((KeyInfoX509Data)clause).Certificates.Count > 0)
                    {
                        certificate =
                        (X509Certificate2)((KeyInfoX509Data)clause).Certificates[0];
                    }
                }
            }

            return signedXml.CheckSignature(certificate, true);
        }

        #endregion

        #region XML Signing

        #region Key management

        public static RSA getRSAFromKey(string key)
        {
            RSA rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(key);
            return rsa;
        }

        #endregion

        #region Detatched signing

        // Sign an XML file and save the signature in a new file. 
        public static void SignDetachedResourceToFile(string URIString, string XmlSigFileName, RSA Key = null, string CertificateFile = "")
        {
            X509Certificate cert = null;
            if (!string.IsNullOrWhiteSpace(CertificateFile))
                cert = new X509Certificate(StreamHelper.GetBytesFromFile(CertificateFile));
            XmlElement xmlDigitalSignature = SignDetachedResource(URIString, XmlSigFileName, Key, cert);
            XMLhelper.XmlToFile(xmlDigitalSignature, XmlSigFileName, false);
        }

        // if Certificate != null, use X509 certificate
        public static XmlElement SignDetachedResource(string URIString = "http://www.microsoft.com", string XmlSigFileName = "XmlSigFile.xml", RSA Key = null, X509Certificate Certificate = null)
        {
            if (Key == null)
                Key = new RSACryptoServiceProvider();

            // Create a SignedXml object.
            SignedXml signedXml = new SignedXml();

            // Assign the key to the SignedXml object.
            signedXml.SigningKey = Key;

            // Create a reference to be signed.
            Reference reference = new Reference();

            // Add the passed URI to the reference object.
            reference.Uri = URIString;

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            // Add an RSAKeyValue KeyInfo (optional; helps recipient find key to validate).
            KeyInfo keyInfo = new KeyInfo();

            if (Certificate == null)
                keyInfo.AddClause(new RSAKeyValue((RSA)Key));
            else // X509 certificate
                keyInfo.AddClause(new KeyInfoX509Data(Certificate));

            signedXml.KeyInfo = keyInfo;

            // Compute the signature.
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save 
            // it to an XmlElement object.
            return signedXml.GetXml();
        }

        // Verify the signature of an XML file and return the result. 
        public static bool VerifyDetachedSignature(string XmlSigFileName)
        {
            FileStream fileStream = new FileStream(XmlSigFileName, FileMode.Open);
            try
            {
                return VerifyDetachedSignature(fileStream);
            }
            catch
            {
                return false;
            }
            finally
            {
                fileStream.Close();
            }
        }

        private static Boolean VerifyDetachedSignature(Stream s)
        {
            // Create a new XML document.
            XmlDocument xmlDocument = new XmlDocument();

            // Load the passed XML file into the document.
            xmlDocument.Load(s);

            // Create a new SignedXML object.
            SignedXml signedXml = new SignedXml();

            // Find the "Signature" node and create a new 
            // XmlNodeList object.
            XmlNodeList nodeList = xmlDocument.GetElementsByTagName("Signature");

            // Load the signature node.
            signedXml.LoadXml((XmlElement)nodeList[0]);

            // Check the signature and return the result. 
            return signedXml.CheckSignature();
        }

        #endregion

        #region Enveloped Signing

        /* Structure of XML Signature (xmldsig)
        <Signature>
            <SignedInfo> (references the signed data and specifies what algorithms are used)
                <CanonicalizationMethod />
                <SignatureMethod />
                <Reference>
                    <Transforms>
                    <DigestMethod> (specifies the hash algorithm before applying the hash)
                    <DigestValue> (contains the result of applying the hash algorithm to the transformed resource)
                </Reference>
                <Reference /> etc.
            </SignedInfo> (Base64 encoded signature result)
            <SignatureValue />
            <KeyInfo /> (optional, usally one or more X.509 certificates)
            <Object /> (contaions signed data if using enveloping sign)
        </Signature>
        */

        // Sign an XML file and save the signature in a new file. 
        public static void SignXmlFile(string FileName, string SignedFileName, RSA Key, bool includeKeyInSignature = false, string certFile = "")
        {
            X509Certificate2 cert = null;
            if (!string.IsNullOrWhiteSpace(certFile))
                cert = new X509Certificate2(StreamHelper.GetBytesFromFile(certFile));

            // Create a new XML document.
            XmlDocument doc = new XmlDocument();

            // Format the document to ignore white spaces.
            doc.PreserveWhitespace = false;

            // Load the passed XML file using it's name.
            doc.Load(new XmlTextReader(FileName));

            SignDocumentEnveloped(doc, Key, includeKeyInSignature, "", cert);

            if (doc.FirstChild is XmlDeclaration)
            {
                doc.RemoveChild(doc.FirstChild);
            }

            // Save the signed XML document to a file specified 
            // using the passed string.
            XmlToFile(doc.DocumentElement, SignedFileName, true);
        }

        // wrapper for SignDocumentEnveloped
        public static string SignXmlEnveloped(string xml, RSA Key, bool includeKeyInSignature = false, string exclusiveNameSpaceToSign = "", X509Certificate2 cert = null)
        {
            if (string.IsNullOrWhiteSpace(xml))
                throw new ArgumentException("xml");

            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.LoadXml(xml);
            SignDocumentEnveloped(doc, Key, includeKeyInSignature, exclusiveNameSpaceToSign, cert);
            return doc.OuterXml;
        }

        // if cert is not null - use X509Certificate as key
        public static void SignDocumentEnveloped(XmlDocument doc, RSA Key, bool includeKeyInSignature = false, string exclusiveNameSpaceToSign = "", X509Certificate2 cert = null)
        {
            if (doc == null)
                throw new ArgumentException("xmlDoc");

            // Create a SignedXml object.
            SignedXml signedXml = new SignedXml(doc);

            // Add the key to the SignedXml document. 
            if (cert == null)
                signedXml.SigningKey = Key;
            else
                signedXml.SigningKey = ((RSA)cert.PrivateKey);

            // Specify a canonicalization method. (Exclusive XML Canonicalization)
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            // Set the InclusiveNamespacesPrefixList property.        
            if (!string.IsNullOrWhiteSpace(exclusiveNameSpaceToSign))
            {
                XmlDsigExcC14NTransform canMethod = (XmlDsigExcC14NTransform)signedXml.SignedInfo.CanonicalizationMethodObject;
                canMethod.InclusiveNamespacesPrefixList = exclusiveNameSpaceToSign;
            }

            // Create a reference to be signed.
            Reference reference = new Reference();
            reference.Uri = "";

            // Add an enveloped transformation to the reference.
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            // Add an RSAKeyValue KeyInfo (optional; helps recipient find key to validate)
            if (includeKeyInSignature)
            {
                KeyInfo keyInfo = new KeyInfo();
                if (cert == null)
                    keyInfo.AddClause(new RSAKeyValue((RSA)Key)); // RSAKeyValue is public part
                else
                    keyInfo.AddClause(new KeyInfoX509Data(cert));
                signedXml.KeyInfo = keyInfo;
            }

            // Compute the signature.
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save 
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            // Append the element to the XML document.
            doc.DocumentElement.AppendChild(doc.ImportNode(xmlDigitalSignature, true));
        }

        // Wrapper for VerifyDocumentEnveloped
        public static Boolean VerifyXmlFile(String Name, string optionalKey = "")
        {
            // Create a new XML document.
            XmlDocument xmlDocument = new XmlDocument();

            // Format using white spaces.
            xmlDocument.PreserveWhitespace = true;

            // Load the passed XML file into the document. 
            xmlDocument.Load(Name);

            return VerifyDocumentEnveloped(xmlDocument, optionalKey);
        }

        // Wrapper for VerifyDocumentEnveloped
        public static Boolean VerifyXmlString(String xml, string optionalKey = "")
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.LoadXml(xml);
            return VerifyDocumentEnveloped(doc, optionalKey);
        }

        // Verify the signature of an XML document and return the result. OptionalKey = RSA key as xmlString
        public static bool VerifyDocumentEnveloped(XmlDocument doc, string optionalKey = "")
        {
            // Check arguments.
            if (doc == null)
                throw new ArgumentException("Doc");

            // Create a new SignedXml object and pass it 
            // the XML document class.
            SignedXml signedXml = new SignedXml(doc);

            // Find the "Signature" node and create a new 
            // XmlNodeList object.
            XmlNodeList nodeList = doc.GetElementsByTagName("Signature");

            // Throw an exception if no or many signatures was found. This functions only supports a single signatur for a document.
            if (nodeList.Count <= 0)
                throw new CryptographicException("Verification failed: No Signature was found in the document.");
            else if (nodeList.Count >= 2)
                throw new CryptographicException("Verification failed: More that one signature was found for the document.");

            // Load the signature node.
            signedXml.LoadXml((XmlElement)nodeList[0]);

            // Check the signature and return the result.
            if (string.IsNullOrWhiteSpace(optionalKey))
                return signedXml.CheckSignature();
            else // using key not in signature
            {
                RSACryptoServiceProvider rsaKey = new RSACryptoServiceProvider();
                rsaKey.FromXmlString(optionalKey);
                return signedXml.CheckSignature(rsaKey);
            }
        }

        #endregion

        #endregion

    }
}
