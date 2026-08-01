using jnUtil;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Security;
using System.Text;

namespace jnUtilTests;

[TestClass]
public class SecureStringExtensionsTests
{
    [TestMethod]
    public void ToSecureStringAndClear_CreatesReadOnlySecureString_AndClearsSource()
    {
        char[] value = "P@ssw0rd!".ToCharArray();
        using SecureString secureString = value.ToSecureStringAndClear();

        Assert.AreSequenceEqual(new char[value.Length], value);
        Assert.AreEqual("P@ssw0rd!", secureString.ToInsecureString());
        Assert.ThrowsExactly<InvalidOperationException>(() => secureString.AppendChar('x'));
    }

    [TestMethod]
    public void ToSecureString_ConvertsPlainText()
    {
        string value = new("sëcrêt🔒".ToCharArray());
        using SecureString secureString = value.ToSecureString();
        Assert.AreEqual("sëcrêt🔒", secureString.ToInsecureString());
    }

    [TestMethod]
    public void IsEqualTo_ReturnsTrue_ForEquivalentSecureStrings()
    {
        using SecureString first = "same value".ToCharArray().ToSecureStringAndClear();
        using SecureString second = "same value".ToCharArray().ToSecureStringAndClear();

        Assert.IsTrue(first.IsEqualTo(second));
    }

    [TestMethod]
    public void IsEqualTo_ReturnsFalse_ForDifferentSecureStrings()
    {
        using SecureString first = "first value".ToCharArray().ToSecureStringAndClear();
        using SecureString second = "second value".ToCharArray().ToSecureStringAndClear();

        Assert.IsFalse(first.IsEqualTo(second));
    }

    [TestMethod]
    public void IsEqualTo_ReturnsFalse_WhenLengthsDiffer()
    {
        using SecureString shorter = "value".ToCharArray().ToSecureStringAndClear();
        using SecureString longer = "value!".ToCharArray().ToSecureStringAndClear();

        Assert.IsFalse(shorter.IsEqualTo(longer));
    }

    [TestMethod]
    public void ToSecureStringAndClear_ThrowsArgumentNullException_ForNullValue()
    {
        Assert.ThrowsExactly<ArgumentNullException>(
            () => SecureStringExtensions.ToSecureStringAndClear(null!));
    }

    [TestMethod]
    public void IsEqualTo_ThrowsArgumentNullException_ForNullFirstValue()
    {
        using SecureString value = "value".ToCharArray().ToSecureStringAndClear();

        Assert.ThrowsExactly<ArgumentNullException>(
            () => SecureStringExtensions.IsEqualTo(null!, value));
    }

    [TestMethod]
    public void IsEqualTo_ThrowsArgumentNullException_ForNullSecondValue()
    {
        using SecureString value = "value".ToCharArray().ToSecureStringAndClear();

        Assert.ThrowsExactly<ArgumentNullException>(
            () => SecureStringExtensions.IsEqualTo(value, null!));
    }

    [TestMethod]
    public void ToSecureString_ConvertsPlainText_AndZerosSourceString()
    {
        const string expectedValue = "sëcrêt🔒";
        string value = new(expectedValue.ToCharArray());

        using SecureString secureString = value.ToSecureString();

        Assert.AreEqual(expectedValue, secureString.ToInsecureString());
        Assert.AreEqual(new string('\0', expectedValue.Length), value);
    }
}

