using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace jnUtil
{
    public static class X509Helper
    {
        const string AKID_OID = "2.5.29.35"; // AKID - authority key identifier
        const string SKID_OID = "2.5.29.14"; // SKID - Subject Key Identifier
        const string KEY_USAGE_OID = "2.5.29.15";
        const string BASIC_CONSTRAINTS_OID = "2.5.29.19";

        public static bool IsSelfSigned(this X509Certificate2 cert) => cert.SubjectName.RawData.SequenceEqual(cert.IssuerName.RawData);

        public static bool IsCA(this X509Certificate2 cert)
        {
            foreach (var ext in cert.Extensions)
            {
                if (ext.Oid.Value.Equals(BASIC_CONSTRAINTS_OID))
                {
                    X509BasicConstraintsExtension e = (X509BasicConstraintsExtension)ext;
                    return e.CertificateAuthority;

                }
            }
            return false;
        }

        public static bool IsForDigitalSignature(this X509Certificate2 cert) => cert.KeyUsages().HasFlag(X509KeyUsageFlags.DigitalSignature);
        
        public static X509KeyUsageFlags KeyUsages(this X509Certificate2 cert)
        {
            foreach (var ext in cert.Extensions)
            {
                if(ext.Oid.Value.Equals(KEY_USAGE_OID))
                {
                    X509KeyUsageExtension kue = (X509KeyUsageExtension)ext;
                    return kue.KeyUsages;
                    
                }
            }
            return 0;
        }

        public static string GetX509Info(X509Certificate2 cert)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(string.Format("{0}Subject: {1}{0}", Environment.NewLine, cert.Subject));
            sb.Append(string.Format("{0}Issuer: {1}{0}", Environment.NewLine, cert.Issuer));
            sb.Append(string.Format("{0}Version: {1}{0}", Environment.NewLine, cert.Version));
            sb.Append(string.Format("{0}Valid Date: {1}{0}", Environment.NewLine, cert.NotBefore));
            sb.Append(string.Format("{0}Expiry Date: {1}{0}", Environment.NewLine, cert.NotAfter));
            sb.Append(string.Format("{0}Thumbprint: {1}{0}", Environment.NewLine, cert.Thumbprint));
            sb.Append(string.Format("{0}Serial Number: {1}{0}", Environment.NewLine, cert.SerialNumber));
            sb.Append(string.Format("{0}Friendly Name: {1}{0}", Environment.NewLine, cert.FriendlyName));
            sb.Append(string.Format("{0}Public Key Format: {1}{0}", Environment.NewLine, cert.Subject));
            sb.Append(string.Format("{0}Raw Data Length: {1}{0}", Environment.NewLine, cert.Subject));
            sb.Append(string.Format("{0}Certificate to string: {1}{0}", Environment.NewLine, cert.Subject));
            sb.Append(string.Format("{0}Certificate to XML String: {1}{0}", Environment.NewLine, cert.Subject));
            return sb.ToString();
        }


        #region IO

        public static byte[] GetPublicKey(X509Certificate2 certificate) => certificate.Export(X509ContentType.Cert);

        // wrapper for GetPublicKey
        public static X509Certificate2 ExportCertificatePublicKey(X509Certificate2 certificate) => new X509Certificate2(GetPublicKey(certificate));

        // wrapper for GetPublicKey, saves public key in .cer file
        public static void SaveX509ToCerFile(X509Certificate2 cert, string filename) => File.WriteAllBytes(filename, GetPublicKey(cert));

        /// <summary>
        /// The PKCS#12 or PFX format is a binary format for storing the server certificate, intermediate certificates, 
        /// and the private key in one encryptable file. PFX files usually have extensions such as .pfx and .p12. 
        /// PFX files are typically used on Windows machines to import and export certificates and private keys.
        /// </summary>
        /// <param name="cert"></param>
        /// <param name="password">null if no password</param>
        public static byte[] X509ToPfx(X509Certificate2 cert, SecureString password)
        {
            if (password == null)
                return cert.Export(X509ContentType.Pfx);
            else
                return cert.Export(X509ContentType.Pfx, password);
        }

        // wrapper for X509ToPfx
        public static void SaveX509ToPfxFile(X509Certificate2 cert, string filename, SecureString password) => File.WriteAllBytes(filename, X509ToPfx(cert, password));

        public static X509Certificate2 X509FromPfx(byte[] pfx, SecureString password)
        {
            X509Certificate2 cert;

            if (password == null)
                cert = new X509Certificate2(pfx);
            else
                cert = new X509Certificate2(pfx, password, X509KeyStorageFlags.Exportable);
            return cert;
        }

        // wrapper for X509FromPfx
        public static X509Certificate2 LoadPfxFromFile(string filename, SecureString password = null)
        {
            using (FileStream fs = File.OpenRead(filename))
            {
                byte[] bytes = new byte[fs.Length];
                fs.Read(bytes, 0, Convert.ToInt32(fs.Length));
                fs.Close();
                return X509FromPfx(bytes, password);
            }
        }

        public static byte[] X509WithChainToPfx(X509Certificate2 certificate, SecureString password, X509Certificate2 signingCert, X509Certificate2Collection chain)
        {
            var certCollection = new X509Certificate2Collection(certificate);
            if (chain != null)
                certCollection.AddRange(chain);

            if (signingCert != null)
            {
                var signingCertWithoutPrivateKey = ExportCertificatePublicKey(signingCert);
                certCollection.Add(signingCertWithoutPrivateKey);

            }

            return certCollection.Export(X509ContentType.Pkcs12, password.ToInsecureString());
        }

        // wrapper for X509WithChainToPfx
        public static void SaveX509WithChainToPfxFile(X509Certificate2 certificate, string filename, SecureString password, X509Certificate2 signingCert, X509Certificate2Collection chain)
            => File.WriteAllBytes(filename, X509WithChainToPfx(certificate, password, signingCert, chain));


        public static (X509Certificate2 certificate, X509Certificate2Collection collection)
            LoadPfxAndCollectionFromFile(string pfxFileName, SecureString password)
        {
            if (string.IsNullOrEmpty(pfxFileName))
            {
                throw new ArgumentException($"{nameof(pfxFileName)} must be a valid filename.", nameof(pfxFileName));
            }
            if (!File.Exists(pfxFileName))
            {
                throw new FileNotFoundException($"{pfxFileName} does not exist. Cannot load certificate from non-existing file.", pfxFileName);
            }
            var certificateCollection = new X509Certificate2Collection();
            certificateCollection.Import(
                pfxFileName,
                password.ToInsecureString(),
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet);

            X509Certificate2 certificate = null;
            var outcollection = new X509Certificate2Collection();
            foreach (X509Certificate2 element in certificateCollection)
            {
                Debug.WriteLine($"Found certificate: {element?.Thumbprint} " +
                    $"{element?.Subject}; PrivateKey: {element?.HasPrivateKey}");
                if (certificate == null && element.HasPrivateKey)
                {
                    certificate = element;
                }
                else
                {
                    outcollection.Add(element);
                }
            }

            if (certificate == null)
            {
                Debug.WriteLine($"ERROR: {pfxFileName} did not " +
                    $"contain any certificate with a private key.");
                return (null, null);
            }
            else
            {
                Debug.WriteLine($"Using certificate {certificate.Thumbprint} " +
                    $"{certificate.Subject}");
                return (certificate, outcollection);
            }

        }

        #endregion

        #region Signing and CA PKI

        // 1. Root CA cert (no issuingCA) or intermediate CA from issuingCA. Import Root into trusted root and intermediate 
        public static X509Certificate2 CreateCACert(string subjectName, X509Certificate2 issuingCa)
        {
            using (ECDsa ecdsa = ECDsa.Create())
            {
                ecdsa.KeySize = 256;
                CertificateRequest request = new CertificateRequest($"CN={subjectName}", ecdsa, HashAlgorithmName.SHA256);

                // Set basic certificate contraints

                // When an extension is marked as critical, a system that verifies the certificate must verify the extension and its contents.
                // If it doesn’t understand the extension, or the contents are invalid, the system must reject the certificate
                bool IsCertificateAuthority = true;
                bool IsLimitedChainLength = true;
                int MaxChainLength = 12;
                bool CriticalExtensionTrue = true;
                request.CertificateExtensions.Add(new X509BasicConstraintsExtension(IsCertificateAuthority, IsLimitedChainLength, MaxChainLength, CriticalExtensionTrue));

                // key usage: Digital Signature and Key Encipherment
                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));

                // AKID - authority key identifier
                if (issuingCa != null)
                {
                    // Set the AuthorityKeyIdentifier. 
                    // There is no built-in support, so it needs to be copied from the Subject Key Identifier of the signing certificate and massaged slightly. 
                    // AuthorityKeyIdentifier is "KeyID=<subject key identifier>"
                    var issuerSubjectKey = issuingCa.Extensions[SKID_OID].RawData; // 2.5.29.14
                    var segment = new ArraySegment<byte>(issuerSubjectKey, 2, issuerSubjectKey.Length - 2);
                    var authorityKeyIdentifier = new byte[segment.Count + 4];
                    // these bytes define the "KeyID" part of the AuthorityKeyIdentifer
                    authorityKeyIdentifier[0] = 0x30;
                    authorityKeyIdentifier[1] = 0x16;
                    authorityKeyIdentifier[2] = 0x80;
                    authorityKeyIdentifier[3] = 0x14;
                    segment.CopyTo(authorityKeyIdentifier, 4);
                    request.CertificateExtensions.Add(new X509Extension(AKID_OID, authorityKeyIdentifier, false));
                }
                else // root cert in chain, use public key
                {
                    byte[] akid = new X509SubjectKeyIdentifierExtension(request.PublicKey, false).RawData;
                    ArraySegment<byte> segment = new ArraySegment<byte>(akid, 2, akid.Length - 2);
                    byte[] authorityKeyIdentifier = new byte[segment.Count + 4];
                    // these bytes define the "KeyID" part of the AuthorityKeyIdentifer
                    authorityKeyIdentifier[0] = 0x30;
                    authorityKeyIdentifier[1] = 0x16;
                    authorityKeyIdentifier[2] = 0x80;
                    authorityKeyIdentifier[3] = 0x14;
                    segment.CopyTo(authorityKeyIdentifier, 4);
                    request.CertificateExtensions.Add(new X509Extension(AKID_OID, authorityKeyIdentifier, false));
                }

                // DPS samples create certs with the device name as a SAN name in addition to the subject name
                var sanBuilder = new SubjectAlternativeNameBuilder();
                sanBuilder.AddDnsName(subjectName);
                var sanExtension = sanBuilder.Build();
                request.CertificateExtensions.Add(sanExtension);

                // Enhanced key usages (maybe not needed for CA cert?)
                request.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(
                        new OidCollection {
                            new Oid("1.3.6.1.5.5.7.3.2"), // TLS Client auth
                            new Oid("1.3.6.1.5.5.7.3.1")  // TLS Server auth
                        },
                        false));

                // add this subject key identifier (SKID)
                request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, !CriticalExtensionTrue));

                // certificate expiry: Valid from Yesterday to Now+365 days
                // Unless the signing cert's validity is less. It's not possible
                // to create a cert with longer validity than the signing cert.
                var notbefore = DateTimeOffset.UtcNow.AddDays(-1);
                if ((issuingCa != null) && (notbefore < issuingCa.NotBefore))
                    notbefore = new DateTimeOffset(issuingCa.NotBefore);

                var notafter = DateTimeOffset.UtcNow.AddDays(365);
                if ((issuingCa != null) && (notafter > issuingCa.NotAfter))
                    notafter = new DateTimeOffset(issuingCa.NotAfter);


                // cert serial is the epoch/unix timestamp (can be any number, required by RFC-5280 to be unique for each certificate a CA issues)
                var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                var unixTime = Convert.ToInt64((DateTime.UtcNow - epoch).TotalSeconds);
                var serial = BitConverter.GetBytes(unixTime);

                // The certificate request is used to create a new certificate
                 
                X509Certificate2 generatedCertificate = null;
                if (issuingCa == null)
                {
                    generatedCertificate = request.CreateSelfSigned(notbefore, notafter);
                    return generatedCertificate; // If it is self-signed, it contains the private key.
                }
                else
                {
                    generatedCertificate = request.Create(issuingCa, notbefore, notafter, serial);
                    return generatedCertificate.CopyWithPrivateKey(ecdsa); // If not, it must be copied along with the private key from the EC DSA object
                }
            }
        }

        // 2.
        public static X509Certificate2 CreateAndSignCertificate(string subjectName, X509Certificate2 signingCertificate)
        {
            if (signingCertificate == null)
                throw new ArgumentNullException(nameof(signingCertificate));

            if (!signingCertificate.HasPrivateKey)
                throw new Exception("Signing cert must have private key");

            if (string.IsNullOrEmpty(subjectName))
                throw new ArgumentException($"{nameof(subjectName)} must be a valid DNS name", nameof(subjectName));

            if (UriHostNameType.Unknown == Uri.CheckHostName(subjectName))
                throw new ArgumentException("Must be a valid DNS name", nameof(subjectName));

            using (var ecdsa = ECDsa.Create())
            {
                ecdsa.KeySize = 256;
                var request = new CertificateRequest($"CN={subjectName}", ecdsa, HashAlgorithmName.SHA256);

                // set basic certificate contraints
                request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));

                // rcf 5280, key usage: Digital Signature, Non Repudiation and Key Encipherment
                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation | X509KeyUsageFlags.KeyEncipherment, true));

                // set the AuthorityKeyIdentifier. There is no built-in 
                // support, so it needs to be copied from the Subject Key 
                // Identifier of the signing certificate and massaged slightly.
                // AuthorityKeyIdentifier is "KeyID=<subject key identifier>"
                var issuerSubjectKey = signingCertificate.Extensions[SKID_OID].RawData;
                var segment = new ArraySegment<byte>(issuerSubjectKey, 2, issuerSubjectKey.Length - 2);
                var authorityKeyIdentifer = new byte[segment.Count + 4];
                // these bytes define the "KeyID" part of the AuthorityKeyIdentifer
                authorityKeyIdentifer[0] = 0x30;
                authorityKeyIdentifer[1] = 0x16;
                authorityKeyIdentifer[2] = 0x80;
                authorityKeyIdentifer[3] = 0x14;
                segment.CopyTo(authorityKeyIdentifer, 4);
                request.CertificateExtensions.Add(new X509Extension(AKID_OID, authorityKeyIdentifer, false));

                // DPS samples create certs with the device name as a SAN name 
                // in addition to the subject name
                var sanBuilder = new SubjectAlternativeNameBuilder();
                sanBuilder.AddDnsName(subjectName);
                var sanExtension = sanBuilder.Build();
                request.CertificateExtensions.Add(sanExtension);

                // request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.NonRepudiation, false));

                // Enhanced key usages
                request.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(
                        new OidCollection {
                            new Oid("1.3.6.1.5.5.7.3.2"), // TLS Client auth
                            new Oid("1.3.6.1.5.5.7.3.1")  // TLS Server auth
                        },
                        false));

                // add this subject key identifier
                request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

                // certificate expiry: Valid from Yesterday to Now+365 days
                // Unless the signing cert's validity is less. It's not possible
                // to create a cert with longer validity than the signing cert.
                var notbefore = DateTimeOffset.UtcNow.AddDays(-1);
                if (notbefore < signingCertificate.NotBefore)
                    notbefore = new DateTimeOffset(signingCertificate.NotBefore);

                var notafter = DateTimeOffset.UtcNow.AddDays(365);
                if (notafter > signingCertificate.NotAfter)
                    notafter = new DateTimeOffset(signingCertificate.NotAfter);

                // cert serial is the epoch/unix timestamp
                var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                var unixTime = Convert.ToInt64((DateTime.UtcNow - epoch).TotalSeconds);
                var serial = BitConverter.GetBytes(unixTime);

                // create and return the generated and signed
                using (var cert = request.Create(signingCertificate, notbefore, notafter, serial))
                {
                    return cert.CopyWithPrivateKey(ecdsa);
                }
            }
        }

        public static byte[][] CreateCertChain(X509Certificate2 CAcert, string subject, int chainLength, SecureString password)
        {
            byte[][] certs = new byte[chainLength][];

            var previousCaCert = CAcert;
            var chain = new X509Certificate2Collection();
            for (var i = 1; i <= chainLength; i++)
            {
                var intermediateCert = CreateCACert($"{subject} - Intermediate {i}", previousCaCert);
                var previousCaCertPublicKey = ExportCertificatePublicKey(previousCaCert);
                certs[i - 1] = X509WithChainToPfx(intermediateCert, password, previousCaCertPublicKey, chain);
                // SaveCertificateToPfxFile(intermediateCert, path + $"Intermediate {i}.pfx", password, previousCaCertPublicKey, chain);
                chain.Add(previousCaCertPublicKey);
                previousCaCert = intermediateCert;
            }
            return certs;
        }

        #endregion

        #region Old

        public static X509Certificate2 CreateSelfSignedCertificate_old(SecureString pwd, string organizationName = "Company", string commonName = "Firstname", string surname = "Lastname")
        {
            byte[] pfx = CreateSelfSignCertificatePfx("O=" + organizationName + ",CN=" + commonName + ",SN=" + surname, DateTime.Now, DateTime.Now.AddYears(3), pwd);
            X509Certificate2 cert = new X509Certificate2(pfx, pwd, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            byte[] publicBytes = cert.RawData;
            using (RSA rsa = cert.GetRSAPrivateKey())
            {
                byte[] dataToSign = Encoding.UTF8.GetBytes("Test");
                byte[] signedData = rsa.SignData(dataToSign, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
                using(RSA rsa2 = new X509Certificate2(publicBytes).GetRSAPublicKey())
                {
                    bool verified = rsa2.VerifyData(dataToSign, signedData, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
                    Debug.Assert(verified, "Signature verification failed");
                }
            }
            
            return cert;
        }

        private static byte[] CreateSelfSignCertificatePfx(string x500, DateTime startTime, DateTime endTime, SecureString password)
        {
            byte[] pfxData;

            if (x500 == null)
            {
                x500 = "";
            }

            SystemTime startSystemTime = ToSystemTime(startTime);
            SystemTime endSystemTime = ToSystemTime(endTime);
            string containerName = Guid.NewGuid().ToString();

            GCHandle dataHandle = new GCHandle();
            IntPtr providerContext = IntPtr.Zero;
            IntPtr cryptKey = IntPtr.Zero;
            IntPtr certContext = IntPtr.Zero;
            IntPtr certStore = IntPtr.Zero;
            IntPtr storeCertContext = IntPtr.Zero;
            IntPtr passwordPtr = IntPtr.Zero;
            // RuntimeHelpers.PrepareConstrainedRegions(); // Obsolete
            try
            {
                Check(NativeMethods.CryptAcquireContextW(
                    out providerContext,
                    containerName,
                    null,
                    1, // PROV_RSA_FULL
                    8)); // CRYPT_NEWKEYSET

                Check(NativeMethods.CryptGenKey(
                    providerContext,
                    1, // AT_KEYEXCHANGE
                    1, // CRYPT_EXPORTABLE
                    out cryptKey));

                IntPtr errorStringPtr;
                int nameDataLength = 0;
                byte[] nameData;

                // errorStringPtr gets a pointer into the middle of the x500 string,
                // so x500 needs to be pinned until after we've copied the value
                // of errorStringPtr.
                dataHandle = GCHandle.Alloc(x500, GCHandleType.Pinned);

                if (!NativeMethods.CertStrToNameW(
                    0x00010001, // X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
                    dataHandle.AddrOfPinnedObject(),
                    3, // CERT_X500_NAME_STR = 3
                    IntPtr.Zero,
                    null,
                    ref nameDataLength,
                    out errorStringPtr))
                {
                    string error = Marshal.PtrToStringUni(errorStringPtr);
                    throw new ArgumentException(error);
                }

                nameData = new byte[nameDataLength];

                if (!NativeMethods.CertStrToNameW(
                    0x00010001, // X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
                    dataHandle.AddrOfPinnedObject(),
                    3, // CERT_X500_NAME_STR = 3
                    IntPtr.Zero,
                    nameData,
                    ref nameDataLength,
                    out errorStringPtr))
                {
                    string error = Marshal.PtrToStringUni(errorStringPtr);
                    throw new ArgumentException(error);
                }

                dataHandle.Free();

                dataHandle = GCHandle.Alloc(nameData, GCHandleType.Pinned);
                CryptoApiBlob nameBlob = new CryptoApiBlob(
                    nameData.Length,
                    dataHandle.AddrOfPinnedObject());

                CryptKeyProviderInformation kpi = new CryptKeyProviderInformation();
                kpi.ContainerName = containerName;
                kpi.ProviderType = 1; // PROV_RSA_FULL
                kpi.KeySpec = 1; // AT_KEYEXCHANGE

                certContext = NativeMethods.CertCreateSelfSignCertificate(
                    providerContext,
                    ref nameBlob,
                    0,
                    ref kpi,
                    IntPtr.Zero, // default = SHA1RSA
                    ref startSystemTime,
                    ref endSystemTime,
                    IntPtr.Zero);
                Check(certContext != IntPtr.Zero);
                dataHandle.Free();

                certStore = NativeMethods.CertOpenStore(
                    "Memory", // sz_CERT_STORE_PROV_MEMORY
                    0,
                    IntPtr.Zero,
                    0x2000, // CERT_STORE_CREATE_NEW_FLAG
                    IntPtr.Zero);
                Check(certStore != IntPtr.Zero);

                Check(NativeMethods.CertAddCertificateContextToStore(
                    certStore,
                    certContext,
                    1, // CERT_STORE_ADD_NEW
                    out storeCertContext));

                NativeMethods.CertSetCertificateContextProperty(
                    storeCertContext,
                    2, // CERT_KEY_PROV_INFO_PROP_ID
                    0,
                    ref kpi);

                if (password != null)
                {
                    passwordPtr = Marshal.SecureStringToCoTaskMemUnicode(password);
                }

                CryptoApiBlob pfxBlob = new CryptoApiBlob();
                Check(NativeMethods.PFXExportCertStoreEx(
                    certStore,
                    ref pfxBlob,
                    passwordPtr,
                    IntPtr.Zero,
                    7)); // EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY

                pfxData = new byte[pfxBlob.DataLength];
                dataHandle = GCHandle.Alloc(pfxData, GCHandleType.Pinned);
                pfxBlob.Data = dataHandle.AddrOfPinnedObject();
                Check(NativeMethods.PFXExportCertStoreEx(
                    certStore,
                    ref pfxBlob,
                    passwordPtr,
                    IntPtr.Zero,
                    7)); // EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY
                dataHandle.Free();
            }
            finally
            {
                if (passwordPtr != IntPtr.Zero)
                {
                    Marshal.ZeroFreeCoTaskMemUnicode(passwordPtr);
                }

                if (dataHandle.IsAllocated)
                {
                    dataHandle.Free();
                }

                if (certContext != IntPtr.Zero)
                {
                    NativeMethods.CertFreeCertificateContext(certContext);
                }

                if (storeCertContext != IntPtr.Zero)
                {
                    NativeMethods.CertFreeCertificateContext(storeCertContext);
                }

                if (certStore != IntPtr.Zero)
                {
                    NativeMethods.CertCloseStore(certStore, 0);
                }

                if (cryptKey != IntPtr.Zero)
                {
                    NativeMethods.CryptDestroyKey(cryptKey);
                }

                if (providerContext != IntPtr.Zero)
                {
                    NativeMethods.CryptReleaseContext(providerContext, 0);
                    NativeMethods.CryptAcquireContextW(
                        out providerContext,
                        containerName,
                        null,
                        1, // PROV_RSA_FULL
                        0x10); // CRYPT_DELETEKEYSET
                }
            }

            return pfxData;
        }

        private static SystemTime ToSystemTime(DateTime dateTime)
        {
            long fileTime = dateTime.ToFileTime();
            SystemTime systemTime;
            Check(NativeMethods.FileTimeToSystemTime(ref fileTime, out systemTime));
            return systemTime;
        }

        private static void Check(bool nativeCallSucceeded)
        {
            if (!nativeCallSucceeded)
            {
                int error = Marshal.GetHRForLastWin32Error();
                Marshal.ThrowExceptionForHR(error);
            }
        }

        
        [StructLayout(LayoutKind.Sequential)]
        internal struct SystemTime
        {
            public short Year;
            public short Month;
            public short DayOfWeek;
            public short Day;
            public short Hour;
            public short Minute;
            public short Second;
            public short Milliseconds;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CryptoApiBlob
        {
            public int DataLength;
            public IntPtr Data;

            public CryptoApiBlob(int dataLength, IntPtr data)
            {
                this.DataLength = dataLength;
                this.Data = data;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CryptKeyProviderInformation
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string ContainerName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string ProviderName;
            public int ProviderType;
            public int Flags;
            public int ProviderParameterCount;
            public IntPtr ProviderParameters; // PCRYPT_KEY_PROV_PARAM
            public int KeySpec;
        }

        internal static class NativeMethods
        {
            [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool FileTimeToSystemTime(
                [In] ref long fileTime,
                out SystemTime systemTime);

            [DllImport("AdvApi32.dll", SetLastError = true, ExactSpelling = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CryptAcquireContextW(
                out IntPtr providerContext,
                [MarshalAs(UnmanagedType.LPWStr)] string container,
                [MarshalAs(UnmanagedType.LPWStr)] string provider,
                int providerType,
                int flags);

            [DllImport("AdvApi32.dll", SetLastError = true, ExactSpelling = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CryptReleaseContext(IntPtr providerContext, int flags);

            [DllImport("AdvApi32.dll", SetLastError = true, ExactSpelling = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CryptGenKey(
                IntPtr providerContext,
                int algorithmId,
                int flags,
                out IntPtr cryptKeyHandle);

            [DllImport("AdvApi32.dll", SetLastError = true, ExactSpelling = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CryptDestroyKey(IntPtr cryptKeyHandle);

            [DllImport("Crypt32.dll", SetLastError = true, ExactSpelling = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CertStrToNameW(
                int certificateEncodingType,
                IntPtr x500,
                int strType,
                IntPtr reserved,
                [MarshalAs(UnmanagedType.LPArray)][Out] byte[] encoded,
                ref int encodedLength,
                out IntPtr errorString);

            [DllImport("Crypt32.dll", SetLastError = true, ExactSpelling = true)]
            public static extern IntPtr CertCreateSelfSignCertificate(
                IntPtr providerHandle,
                [In] ref CryptoApiBlob subjectIssuerBlob,
                int flags,
                [In] ref CryptKeyProviderInformation keyProviderInformation,
                IntPtr signatureAlgorithm,
                [In] ref SystemTime startTime,
                [In] ref SystemTime endTime,
                IntPtr extensions);

            [DllImport("Crypt32.dll", SetLastError = true, ExactSpelling = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CertFreeCertificateContext(IntPtr certificateContext);

            [DllImport("Crypt32.dll", SetLastError = true, ExactSpelling = true)]
            public static extern IntPtr CertOpenStore(
                [MarshalAs(UnmanagedType.LPStr)] string storeProvider,
                int messageAndCertificateEncodingType,
                IntPtr cryptProvHandle,
                int flags,
                IntPtr parameters);

            [DllImport("Crypt32.dll", SetLastError = true, ExactSpelling = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CertCloseStore(IntPtr certificateStoreHandle, int flags);

            [DllImport("Crypt32.dll", SetLastError = true, ExactSpelling = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CertAddCertificateContextToStore(
                IntPtr certificateStoreHandle,
                IntPtr certificateContext,
                int addDisposition,
                out IntPtr storeContextPtr);

            [DllImport("Crypt32.dll", SetLastError = true, ExactSpelling = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CertSetCertificateContextProperty(
                IntPtr certificateContext,
                int propertyId,
                int flags,
                [In] ref CryptKeyProviderInformation data);

            [DllImport("Crypt32.dll", SetLastError = true, ExactSpelling = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool PFXExportCertStoreEx(
                IntPtr certificateStoreHandle,
                ref CryptoApiBlob pfxBlob,
                IntPtr password,
                IntPtr reserved,
                int flags);
        }

        #endregion
    }
}
