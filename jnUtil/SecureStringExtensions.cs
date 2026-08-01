using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace jnUtil;

public static class SecureStringExtensions
{

    // usage:
    // char[] pass = "secret".ToCharArray();
    // SecureString securePassword = pass.ToSecureStringAndClear();
    public static SecureString ToSecureStringAndClear(this char[] value)
    {
        ArgumentNullException.ThrowIfNull(value);
        SecureString result = new();

        try
        {
            foreach (char character in value)
                result.AppendChar(character);

            result.MakeReadOnly();
            return result;
        }
        finally
        {
            Array.Clear(value);
        }
    }

    public static SecureString ToSecureString(this string plainStr)
    {
        try
        {
            return ToSecureStringAndClear(plainStr.ToCharArray());
        }
        finally
        {
            plainStr.ZeroString();
        }
    }

    public static bool IsEqualTo(this SecureString ss1, SecureString ss2)
    {
        ArgumentNullException.ThrowIfNull(ss1);
        ArgumentNullException.ThrowIfNull(ss2);

        IntPtr bstr1 = IntPtr.Zero;
        IntPtr bstr2 = IntPtr.Zero;

        try
        {
            bstr1 = Marshal.SecureStringToBSTR(ss1);
            bstr2 = Marshal.SecureStringToBSTR(ss2);

            int length1 = Marshal.ReadInt32(bstr1, -sizeof(int));
            int length2 = Marshal.ReadInt32(bstr2, -sizeof(int));

            if (length1 != length2)
                return false;

            int difference = 0;

            for (int index = 0; index < length1; index++)
                difference |= Marshal.ReadByte(bstr1, index) ^ Marshal.ReadByte(bstr2, index);

            return difference == 0;
        }
        finally
        {
            if (bstr2 != IntPtr.Zero)
                Marshal.ZeroFreeBSTR(bstr2);

            if (bstr1 != IntPtr.Zero)
                Marshal.ZeroFreeBSTR(bstr1);
        }
    }

    public static string ToInsecureString(this SecureString secureStr) => 
        new System.Net.NetworkCredential(string.Empty, secureStr).Password;
}
