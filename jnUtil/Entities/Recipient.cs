namespace jnUtil.Entities
{
    public record class Recipient : PostalAddress
    {
        public string FirstName { get; set; } = "";
        public string LastName { get; set; } = "";
        public bool IsCompany { get; set; }
        public string FullName => IsCompany ? LastName : (!string.IsNullOrWhiteSpace(FirstName) ? FirstName + " " : "") + LastName;

        public override string ToString() => FullName + " " + base.ToString();
    }
}
