using System;
using System.Collections.Generic;
using System.Text;

namespace jnUtil
{
    public static class DateTimeHelper
    {

        public static string GetDateTimeNowString()
        {
            DateTime d = DateTime.Now;
            return d.ToShortDateString() + " " + d.ToShortTimeString();
        }

        // 2011-10-10, 09:00 - 2011-12-12, 12:00
        // 2010-10-10, 09:00-12:00
        // 2010-10-10 - 2010-12-12
        // 2010-10-10
        public static string ToDateInterval(DateTime d1, DateTime d2, bool time = false)
        {
            string ret = "";
            bool single = d1.Date == d2.Date;
            ret += ToIsoDate(d1, false);
            if (time)
            {
                ret += ", ";
                ret += d1.ToString("t");
            }

            else if (!single)
            {
                ret += " - ";
                ret += ToIsoDate(d2, false);
            }

            if (single && time)
            {
                ret += "-";
                ret += d2.ToString("t");
            }

            else if (time)
            {
                ret += " - ";
                ret += d2.ToString("yyyy-MM-dd");
                ret += ", ";
                ret += d2.ToString("t");
            }
            return ret;
        }

        public static string ToIsoDate(this DateTime d, bool time = false)
        {
            
                if (time)
                    return d.ToString("yyyy-MM-dd HH:mm");
                else
                    return d.ToString("yyyy-MM-dd");

            // DateTime to W3C dateTime string
            // return d.ToString("yyyy-MM-ddTHH:mm:ss.fffffffzzz");
        }
    
        public static DateTime FromIsoDate(this string IsoDate, bool time, string cultureInfo = "sv-SE")
        {
            string formatString;
            if (time)
                formatString = "yyyy-MM-dd HH:mm"; 
                //formatString = "yyyy-MM-ddTHH:mm:ss.fffffffzzz"; // W3C dateTime string to DateTime 
            else
                formatString = "yyyy-MM-dd";

            System.Globalization.CultureInfo cInfo = new System.Globalization.CultureInfo(cultureInfo, true);
            try
            {
                return DateTime.ParseExact(IsoDate, formatString, cInfo);
            }
            catch (Exception e)
            {
                throw new ArgumentException($"Could not parse {IsoDate} as datetime: {e.Message}");
            }

        }

        public static string ToWC3DateTime(this DateTime datetime, bool exact = false) => exact ? datetime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffffzzz") : datetime.ToUniversalTime().ToString("s") + "Z";

        public static DateTime FromWC3DateTime(this string wc3DateTime, bool toLocal = false) => toLocal ? DateTime.Parse(wc3DateTime).ToLocalTime() : DateTime.Parse(wc3DateTime).ToUniversalTime();

        public static DateTime FromUnixTimestamp(this double timestamp)
        {
            DateTime origin = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            return origin.AddSeconds(timestamp);
        }

        public static double ToUnixTimestamp(this DateTime date)
        {
            DateTime origin = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            TimeSpan diff = date.ToUniversalTime() - origin;
            return Math.Floor(diff.TotalSeconds);
        }

        public static long TicksFrom1970() => (DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc)).Ticks;

        // Usage:
        // Second: now.Trim(TimeSpan.TicksPerSecond);
        // Minute: now.Trim(TimeSpan.TicksPerMinute);
        // Seconds: now.Trim(TimeSpan.TicksPerSecond);
        public static DateTime Trim(this DateTime date, long ticks) => new DateTime(date.Ticks - (date.Ticks % ticks), date.Kind);
    }
}
