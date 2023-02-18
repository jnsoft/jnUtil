using jnUtil;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security;
using System.Text;

namespace jnUtilTests
{
    [TestClass]
    public class DateTests
    {
        [TestMethod]
        public void IsoDateStringTests()
        {
            // Arrange
            string isodate = "2020-01-01";
            string isodatetime = "2020-01-01 20:22";

            // Act
            DateTime isodateD = isodate.FromIsoDate(false, "sv-SE");
            DateTime isodateDT = isodatetime.FromIsoDate(true, "sv-SE");

            string isodateD_parsed = isodateD.ToIsoDate(false);
            string isodateDT_parsed = isodateDT.ToIsoDate(true);

            // Assert
            Assert.AreEqual(isodate, isodateD_parsed, $"To / From IsoDate failed: {isodate} vs {isodateD_parsed}");
            Assert.AreEqual(isodatetime, isodateDT_parsed, $"To / From IsoDate failed: {isodate} vs {isodateD_parsed}");
        }

        [TestMethod]
        public void W3cDatetimeTests()
        {
            // Arrange
            DateTime utcnow = DateTime.UtcNow;
            DateTime now = DateTime.Now;

            // Act
            string s_utcnow = utcnow.ToWC3DateTime(true);
            string s_now = now.ToWC3DateTime(true);
            DateTime utcnow_parsed = s_utcnow.FromWC3DateTime(false);
            DateTime now_parsed = s_now.FromWC3DateTime(true);

            DateTime utcnow2 = utcnow.Trim(TimeSpan.TicksPerSecond);
            DateTime now2 = now.Trim(TimeSpan.TicksPerSecond);

            string s_utcnow2 = utcnow2.ToWC3DateTime(false);
            string s_now2 = now2.ToWC3DateTime(false);
            DateTime utcnow_parsed2 = s_utcnow2.FromWC3DateTime(false);
            DateTime now_parsed2 = s_utcnow2.FromWC3DateTime(true);

            // Assert
            Assert.AreEqual(utcnow, utcnow_parsed);
            Assert.AreEqual(now, now_parsed);
            Assert.AreEqual(utcnow2, utcnow_parsed2);
            Assert.AreEqual(now2, now_parsed2);

        }

    }
}
