using jnUtil;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace jnUtilTests
{
    [TestClass]
    public class NumericTests
    {
        [TestMethod]
        public void DoubleNearlyEqualTest()
        {
            // Arrange
            double d1 = 0.1;
            double d2 = 0.4;
            double d3 = 0.3;

            // Act
            double diff = d2-d3;
            bool test = NumericHelper.IsNearlyEqual(d1, diff);


            // Assert
            Assert.AreNotEqual(d1, diff);
            Assert.IsTrue(test, $"Assert failed: {d1} does not nearly equals {diff}");
        }
    }
}
