using jnUtil;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace jnUtilTests
{
    [TestClass]
    public class CSVTests
    {
        private string CSV_STR = $"1,1.0,\",\"{Environment.NewLine}2,2.0,;";

        [TestMethod]
        public void ReadCSV()
        {
            // Act
            string[][] parsed = CSVHelper.ReadCSV(CSV_STR, ",", false);

            // Assert
            Assert.IsNotNull(parsed);
            Assert.AreEqual(2, parsed.Length);
            Assert.IsNotNull(parsed[0]);
            Assert.AreEqual(3, parsed[0].Length);
            Assert.AreEqual(3, parsed[1].Length);
            Assert.AreEqual("1",parsed[0][0]);
            Assert.AreEqual("2", parsed[1][0]);
            Assert.AreEqual(",", parsed[0][2]);
        }

        [TestMethod]
        public void WriteCSV()
        {
            // Arrange
            string[][] mat = new string[2][];
            mat[0] = new string[] {"1 ", " 1.0 ", "  ," };
            mat[1] = new string[] { "2", "2.0", ";  " };
            ;

            // Act
            string csv = CSVHelper.WriteCSV(mat, ",", true, false);

            // Assert
            Assert.IsNotNull(csv);

            Assert.AreEqual(CSV_STR, csv);
        }
    }
}
