using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace jnUtil
{
    // The Cryptographic Message Syntax (CMS) is the IETF's standard for cryptographically protected messages. 
    // It can be used by cryptographic schemes and protocols to digitally sign, digest, authenticate or encrypt any form of digital data.
    // CMS is based on the syntax of PKCS #7, which in turn is based on the Privacy-Enhanced Mail standard. 
    // The newest version of CMS (as of 2009) is specified in RFC 5652 (but see also RFC 5911 for updated ASN.1 modules conforming to ASN.1 2002).
    // The architecture of CMS is built around certificate-based key management, such as the profile defined by the PKIX working group.
    // CMS is used as the key cryptographic component of many other cryptographic standards, such as S/MIME, PKCS #12 and the RFC 3161 digital timestamping protocol.
    // OpenSSL is open source software that can encrypt, decrypt, sign and verify, compress and uncompress CMS documents.
    public static class CMSHelper
    {
        /// <summary>
        /// Detatched signing
        /// </summary>
        /// <param name="msg">data to sign</param>
        /// <param name="cert"></param>
        /// <param name="digestAlg"></param>
        /// <returns>PKCS7 certificate (signature)</returns>
        public static byte[] Sign(byte[] msg, X509Certificate2 cert, X509IncludeOption IncludeOption = X509IncludeOption.EndCertOnly, string digestAlg = "SHA256")
        {
            ContentInfo contentInfo = new ContentInfo(msg);
            SignedCms cms = new SignedCms(contentInfo, true);
            CmsSigner cmsSigner = new CmsSigner(cert)
            {
                DigestAlgorithm = new Oid(digestAlg),
                IncludeOption = IncludeOption
            };

            cms.ComputeSignature(cmsSigner);
            cms.CheckSignature(true);

            return cms.Encode();
        }

        /// <summary>
        /// Verify the signatures on the detatched signed CMS/PKCS#7
        /// </summary>
        /// <param name="msg">data that was signed</param>
        /// <param name="pkcs7Sig">Pkcs7 signature</param>
        /// <param name="verifySignatureOnly"></param>
        /// <param name="cert">A X509Certificate2 object that can be used to validate the certificate chain. 
        /// If no additional certificates are to be used to validate the certificate chain, use Verify(byte[], byte[], bool) </param>
        /// <returns></returns>
        public static bool Verify(byte[] msg, byte[] pkcs7Sig, bool verifySignatureOnly, X509Certificate2 cert)
        {
            ContentInfo contentInfo = new ContentInfo(msg);
            SignedCms cms = new SignedCms(contentInfo, true);
            cms.Decode(pkcs7Sig);
            try
            {
                cms.CheckSignature(new X509Certificate2Collection(cert), verifySignatureOnly);
                return true;
            }
            catch (Exception e)
            {
#if DEBUG
                Debug.WriteLine("Error: " + e.Message);
#endif
                return false;
            }
        }

        /// <summary>
        /// Verify the signatures on the detatched signed CMS/PKCS#7
        /// </summary>
        /// <param name="msg">data that was signed</param>
        /// <param name="pkcs7Sig">Pkcs7 signature</param>
        /// <param name="verifySignatureOnly"></param>
        /// <returns></returns>
        public static bool Verify(byte[] msg, byte[] pkcs7Sig, bool verifySignatureOnly)
        {
            try
            {
                ContentInfo contentInfo = new ContentInfo(msg);
                SignedCms cms = new SignedCms(contentInfo, true);
                cms.Decode(pkcs7Sig);
                try
                {
                    cms.CheckSignature(verifySignatureOnly);
                    return true;
                }
                catch (CryptographicException cex)
                {
#if DEBUG
                    Debug.WriteLine("Signature is not valid: " + cex.Message);
#endif
                    return false;
                }
            }
            catch (Exception e)
            {
#if DEBUG
                Debug.WriteLine("Error: " + e.Message);
#endif
                return false;
            }
        }

        // trying to manually verify certificate chain
        public static bool Verify(byte[] msg, byte[] pkcs7Sig)
        {
            ContentInfo contentInfo = new ContentInfo(msg);
            SignedCms cms = new SignedCms(contentInfo, true);
            cms.Decode(pkcs7Sig);
            try
            {
                cms.CheckSignature(true);
                try
                {
                    foreach (X509Certificate2 SignatureCertificate in cms.Certificates)
                    {
                        var certChain = new X509Chain(false); // true = machineContext, false = currentUserContext
                        certChain.Build(SignatureCertificate); // Build the certificate chain from the signers certificate
                        certChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        foreach (X509ChainElement chainElement in certChain.ChainElements)
                        {
                            if (chainElement.Certificate.Verify())
                                return false; // Certificate not valid, check chainElement.ChainElementStatus
                        }
                    }
                    return true;
                }
                catch (Exception innerEx)
                {
#if DEBUG
                    Debug.WriteLine("Certificate not valid: " + innerEx.Message);
#endif
                    return false;
                }
            }
            catch (CryptographicException cex)
            {
#if DEBUG
                Debug.WriteLine("Signature is not valid: " + cex.Message);
#endif
                return false;
            }
            catch (Exception e)
            {
#if DEBUG
                Debug.WriteLine("Error: " + e.Message);
#endif
                return false;
            }
        }

        // Content is not detached, the message content is included in the SignedCms message
        private static bool Verify(byte[] pkcs7Sig, X509Certificate2 cert)
        {
            SignedCms cms = new SignedCms();
            cms.Decode(pkcs7Sig);
            try
            {
                cms.CheckSignature(new X509Certificate2Collection(cert), false);
                return true;
            }
            catch (Exception e)
            {
#if DEBUG
                Debug.WriteLine("Error: " + e.Message);
#endif
                return false;
            }
        }

        private static bool Verify(byte[] pkcs7Sig)
        {
            SignedCms cms = new SignedCms();
            cms.Decode(pkcs7Sig);
            try
            {
                cms.CheckSignature(true);
                return true;
            }
            catch (Exception e)
            {
#if DEBUG
                Debug.WriteLine("Error: " + e.Message);
#endif
                return false;
            }
        }

    }
}
