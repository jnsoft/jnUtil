using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace jnUtil
{
    public class _Address
    {
        public string Street { get; set; }
        public string Number { get; set; }
        public string Letter { get; set; }
        public string Entrance { get; set; }
        public string Apartment { get; set; }

        public string Address
        {
            get
            {
                StringBuilder sb = new StringBuilder();
                sb.Append(Street);
                if (!string.IsNullOrWhiteSpace(Number))
                {
                    sb.Append(" " + Number);
                    if (!string.IsNullOrWhiteSpace(Letter))
                        sb.Append(Letter);
                    if (!string.IsNullOrWhiteSpace(Entrance))
                        sb.Append(" " + Entrance);
                    if (!string.IsNullOrWhiteSpace(Apartment))
                        sb.Append(" " + Apartment);
                }

                return sb.ToString();
            }
        }

        public const int SPLIT_LENGTH = 16;

        public override string ToString() => Address;

        public static _Address SplitAddress(string address)
        {
            address = address.Trim();
            return new _Address
            {
                Street = getAddressPart(address, @"^.*?(?=\d)"),
                Number = getAddressPart(address, @"(\s+)(\d{1,4}-\d{1,4}|\d{1,4})(?=\D|$)"),
                Letter = getAddressPart(address, @"(?<=[A-Za-zÅÄÖåäö]+\s+(\d{1,4}-\d{1,4}|\d{1,4})+\s* ?)([A-Za-zÅÄÖåäö]{1,2})(?=\s|$)"),
                Entrance = getAddressPart(address, @"(?<=[A-Za-zÅÄÖåäö]+\s+(\d{1,4}-\d{1,4}|\d{1,4})+\s*[A-Za-zÅÄÖåäö]{1,2}\s+ ?)(([uU]([vVhH]|\d{1,2}))|([A-Za-z]{1,2}\d{1,2}))(?=\s|$)"),
                Apartment = getAddressPart(address, @"(?<=\d+\D+)(\d{4})(?=$)")
            };
        }

        public static string GetNumber(string addressPlace)
        {
            return getAddressPart(addressPlace, @"(\d{1,4}-\d{1,4}|\d{1,4})");
        }

        public static string GetLetter(string addressPlace)
        {
            return getAddressPart(addressPlace, @"(?<=\d *)([A-Za-zÅÄÖåäö]{1,2})(?=\s|$)");
        }

        public static string GetEntrance(string addressPlace)
        {
            return getAddressPart(addressPlace, @"(?<=\s *)(([uU]([vVhH]|\d{1,2}))|([A-Za-z]{1,2}\d{1,2}))(?=\s|$)");
        }

        public static string[] LineBreakStreetName(string street, int len = 0, bool forceSplit = false)
        {
            street = street.Clean();

            if (len > 0)
            {
                string s1 = "", s2 = "";
                if (street.Length <= len)
                    return new string[1] { street };

                else if (street.Length < 2 * len)
                {
                    s1 = street.Substring(0, len - 1) + "-";
                    s2 = street.Substring(len - 1);
                    return new string[2] { s1, s2 };
                }

                else
                {
                    len = street.Length / 2 + 1;
                    s1 = street.Substring(0, len - 1) + "-";
                    s2 = street.Substring(len - 1);
                    return new string[2] { s1, s2 };
                }
            }

            else
            {

                string[] ss = street.Split(' ');

                if (ss.Count() < 2 && !forceSplit || street.Length < _Address.SPLIT_LENGTH)
                    return new string[1] { street };

                else if (ss.Count() == 2)
                    return new string[2] { ss[0], ss[1] };

                else if (forceSplit)
                {
                    int splitPoint = street.Length / 2;
                    return new string[] { street.Substring(0, splitPoint) + "-", street.Substring(splitPoint) };
                }

                else // at least two words, together at least SPLIT_LENGTH
                {
                    int best = 0;
                    int diff = 0;
                    int split = ss.Length;

                    List<string> upper = new List<string>();
                    List<string> lower = new List<string>();

                    foreach (string s in ss)
                        upper.Add(s);

                    diff = upper.Select(x => x.Length).Sum() - lower.Select(x => x.Length).Sum();
                    best = diff;

                    for (int i = 0; i < ss.Length; i++)
                    {
                        if (Math.Abs(diff) < best)
                        {
                            best = diff;
                            split = ss.Length - i;
                        }
                        upper.RemoveAt(upper.Count() - 1);
                        lower.Add(ss[ss.Length - (i + 1)]);
                        diff = upper.Select(x => x.Length).Sum() - lower.Select(x => x.Length).Sum();
                    }
                    String.Join(" ", ss, 0, split);
                    return new string[2] { String.Join(" ", ss, 0, split), String.Join(" ", ss, split, ss.Length - split) };

                }
            }
        }

        private static string getAddressPart(string address, string pattern)
        {
            return Regex.Match(address, pattern).ToString().Trim();
        }
    }

    public class _PostalAddress : _Address
    {
        public int PostalCode { get; set; }
        public string TownName { get; set; }
        public string PostalAddress { get { return PostalCode.ToString() + " " + TownName; } }

        public override string ToString() => base.ToString() + " " + PostalAddress;
    }

    public class _Recipient : _PostalAddress
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public bool IsComany { get; set; }
        public string Name => IsComany ? LastName : (!string.IsNullOrWhiteSpace(FirstName) ? FirstName + " " : "") + LastName;

        public override string ToString() => Name + " " + base.ToString();
    }
}
