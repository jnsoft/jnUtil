using System.Text.RegularExpressions;

namespace jnUtil
{
    public static class StringUtils
    {
        // Encodings: ibm852: Encoding.GetEncoding(852), Windows-1252: Encoding.GetEncoding(1252), iso-8859-1: Encoding.GetEncoding(28591)

        private static char[] bytePrefix = "KMGT".ToArray();

        public static string ToStringFromByte(this byte[] bytes, bool UTF8Encoding = true)
        {
            if (UTF8Encoding)
                return Encoding.UTF8.GetString(bytes);
            else
            {
                char[] chars = new char[bytes.Length / sizeof(char)];
                System.Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);
                return new string(chars);
            }
        }

        public static byte[] ToByte(this string str, bool UTF8Encoding = true)
        {
            if (UTF8Encoding)
                return Encoding.UTF8.GetBytes(str);
            else
            {
                byte[] bytes = new byte[str.Length * sizeof(char)];
                System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
                return bytes;
            }
        }

        public static string ToAsciiChar(this byte val) => Char.ConvertFromUtf32(val);

        public static string RotateLeft(string s, int n = 1) => s.Substring(n) + s.Substring(0, n);

        public static string RotateRight(string s, int n = 1) => s.Substring(s.Length - n) + s.Substring(0, s.Length - n);

        public static string Reverse(this string s)
        {
            char[] charArray = s.ToCharArray();
            Array.Reverse(charArray);
            return new string(charArray);
        }

        public static string Left(this string str, int length)
        {
            if (length < 0)
                throw new ArgumentOutOfRangeException("length", length, "length must be > 0");
            else if (length == 0 || str.Length == 0)
                return "";
            else if (str.Length <= length)
                return str;
            else
                return str.Substring(0, length);
        }

        public static string Right(this string str, int length)
        {
            if (length < 0)
                throw new ArgumentOutOfRangeException("length", length, "length must be > 0");
            else if (length == 0 || str.Length == 0)
                return "";
            else if (str.Length <= length)
                return str;
            else
                return str.Substring(str.Length - length, length);
        }

        public static string Clean(this string s, bool removeDiacritic = false)
        {
            if (removeDiacritic)
                s = s.Where(c => CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.NonSpacingMark).ToString();

            return Regex.Replace(s, @"\s+", " ").Trim();
        }

        public static string RemoveTags(this string s) => Regex.Replace(s, "<[^>]*>", " ");

        public static string GetErrorMsg(this Exception e, bool getAll = false)
        {
            StringBuilder s = new StringBuilder();
            s.Append(e.Message);
            if (getAll)
            {
                while (e.InnerException != null)
                {
                    s.Append("-> " + e.InnerException.Message);
                    e = e.InnerException;
                }
            }
            return s.ToString();

        }

        public static string ToBytesPrettyPrint(Int64 bytes)
        {
            int i = -1;
            double size = bytes;
            while (size > 1024 && i < 4)
            {
                i++;
                size /= 1024;
            }

            return Math.Round(size, 0).ToString() + (i >= 0 ? bytePrefix[i].ToString() : "") + "B";

        }

        public static bool ReadNumber(string s, out int i)
        {
            if (Int32.TryParse(Regex.Replace(s, @"\D", ""), out i))
                return true;
            else
                return false;
        }

        public static double ReadDouble(string d) => Double.Parse(d, CultureInfo.InvariantCulture);

        public static bool IsPalindrome(this string s)
        {
            for (int i = 0; i < s.Length / 2; i++)
            {
                if (s[i] != s[s.Length - i - 1])
                    return false;
            }
            return true;
        }

        public static string ArrayToString<T>(T[] arr, char delimeter = ',', bool spaces = false)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < arr.Length; i++)
            {
                sb.Append(arr[i].ToString());
                if (i < arr.Length - 1)
                {
                    sb.Append(delimeter);
                    if (spaces)
                        sb.Append(' ');
                }
            }
            return sb.ToString();
        }

        public static int NoOfLines(this string s)
        {
            int count = 1;
            int start = 0;
            while ((start = s.IndexOf('\n', start)) != -1)
            {
                count++;
                start++;
            }
            return count;
        }

        public static string[] SplitToLines(this string text) => Regex.Split(text, "\r\n|\r|\n");

        public static string IntToWords(this int n)
        {
            if (n > 1000 || n < 0)
                throw new ArgumentException("N must be in the interval [0,1000]");
            List<string> number = new List<string>();
            string[] words = new string[20] { "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen" };
            string[] tens = new string[8] { "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety" };

            if (n < 20)
                return words[n];

            string m = n.ToString();
            int strIndex = m.Length - 1;

            int one = Int32.Parse(m[strIndex--].ToString());
            int ten = Int32.Parse(m[strIndex--].ToString());

            string tenOne = "";
            if (ten > 1)
            {
                tenOne = tens[ten - 2] + (one == 0 ? "" : "-" + words[one]);
            }
            else
            {
                if (ten != 0 || one != 0)
                    tenOne = words[Int32.Parse(ten.ToString() + one.ToString())];
            }


            if (m.Length == 2)
                return tenOne;

            int hundred = Int32.Parse(m[strIndex--].ToString());
            string hundredTenOne = "";
            if (hundred != 0)
            {
                hundredTenOne = words[hundred] + " hundred" + (tenOne.Length > 0 ? " and " + tenOne : "");
            }


            if (m.Length == 3)
                return hundredTenOne;

            return "one thousand";

        }

        public static string GetLuhnCheckDigit(string number)
        {
            number = Regex.Replace(number, @"\D", "");
            var sum = 0;
            var alt = true;
            var digits = number.ToCharArray();
            for (int i = digits.Length - 1; i >= 0; i--)
            {
                var curDigit = (digits[i] - 48);
                if (alt)
                {
                    curDigit *= 2;
                    if (curDigit > 9)
                        curDigit -= 9;
                }
                sum += curDigit;
                alt = !alt;
            }
            if ((sum % 10) == 0)
            {
                return "0";
            }
            return (10 - (sum % 10)).ToString();
        }

        public static bool IsLuhnCheckOK(string number)
        {
            number = Regex.Replace(number, @"\D", "");
            var total = 0;
            var alt = false;
            var digits = number.ToCharArray();
            for (int i = digits.Length - 1; i >= 0; i--)
            {
                var curDigit = (int)char.GetNumericValue(digits[i]);
                if (alt)
                {
                    curDigit *= 2;
                    if (curDigit > 9)
                        curDigit -= 9;
                }
                total += curDigit;
                alt = !alt;
            }
            return total % 10 == 0;
        }

        #region Social Security Numbers

        public static string SocialSecurityNo(bool Century, bool Hyphen)
        {
            int y = DateTime.Now.Year;

            Random r = new Random();

            string nr = "";
            nr += r.Next(y - 100, y - 1); // år

            int m = r.Next(1, 12); // månad
            nr += m.ToString().PadLeft(2, '0');

            int d = 30;
            if (m == 2)
                d = 28;
            else if (m == 1 || m == 3 || m == 5 || m == 7 || m == 8 || m == 10 || m == 12)
                d = 31;

            nr += r.Next(1, d).ToString().PadLeft(2, '0'); // dag

            if (Hyphen)
                nr += "-";

            nr += r.Next(1, 999).ToString().PadLeft(3, '0');
            nr += GetLuhnCheckDigit(Right(nr, nr.Length - 2));

            if (Century)
                return nr;
            else
                return Right(nr, nr.Length - 2);
        }

        public static bool IsSocialSecurityNo(string nr, bool strict)
        {
            if (string.IsNullOrWhiteSpace(nr))
                return false;
            if (strict && (Regex.IsMatch(nr, @"[^\d-\+]") || nr.Length < 10 || nr.Length > 13))
                return false;

            nr = Regex.Replace(nr, @"\D", ""); // ta bort allt utom siffror

            if (!Regex.IsMatch(nr, @"\d{10}|\d{12}")) // 10 eller 12 tecken (århundrade först...)
                return false;

            if (nr.Length == 12 && (Int32.Parse(Left(nr, 4)) < 1840 || Int32.Parse(Left(nr, 4)) > DateTime.Today.Year))
                return false;
            else
                return IsLuhnCheckOK(Right(nr, 10));
        }

        public static string FormatSocialSecurityNo(string nr, bool Century, bool Hyphen)
        {
            if (!IsSocialSecurityNo(nr, true))
                return string.Empty;

            nr = Regex.Replace(nr, @"\D", ""); // remove all but numbers

            if (Hyphen)
                nr = nr.Insert(nr.Length - 4, "-");

            if (nr.Length > 11 && !Century)
                return (Right(nr, nr.Length - 2));

            else if (Century && nr.Length < 12) //99 01 01 -> 2099 01 01 -> 1999 xx xx  || 45 01 01 -> 2045 -> 1945 || 12 01 01 -> 2012 01 01 ->
            {
                DateTime d = new DateTime();
                bool success = DateTime.TryParse(DateTime.Today.Year.ToString().Left(2) + Left(nr, 2) + "-" + Right(Left(nr, 4), 2) + "-" + Right(Left(nr, 6), 2), out d);

                if (DateTime.Compare(d, DateTime.Today) >= 0) // d is greater or equal
                    return (DateTime.Today.Year - 100).ToString().Left(2) + nr;
                else
                    return DateTime.Today.Year.ToString().Left(2) + nr;
            }

            return nr;
        }

        #endregion

        #region File handeling

        public static IEnumerable<string> ReadLinesFromFileSafe(string filename, Encoding encoding = null)
        {
            if (encoding == null)
                encoding = Encoding.UTF8;

            using (FileStream logFileStream = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                using (StreamReader logFileReader = new StreamReader(logFileStream, encoding))
                {
                    while (!logFileReader.EndOfStream)
                    {
                        string line = logFileReader.ReadLine();
                        yield return line;
                        // Your code here
                    }

                    // Clean up
                    logFileReader.Close();
                }
                logFileStream.Close();
            }
        }

        public static void ToFile(this string s, string filename, bool append = false, Encoding encoding = null)
        {
            if (encoding == null)
                encoding = Encoding.UTF8;

            if (File.Exists(filename) && !append)
                File.Delete(filename);

            using (StreamWriter sw = new StreamWriter(filename, append, encoding))
            {
                sw.Write(s);
            }
        }

        public static int CountLinesInFile(string filename)
        {
            int count = 0;
            using (StreamReader r = new StreamReader(filename))
            {
                string line;
                while ((line = r.ReadLine()) != null)
                    count++;
            }
            return count;
        }

        #endregion
    }
}
