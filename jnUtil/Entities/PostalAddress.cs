namespace jnUtil.Entities
{
    public record class PostalAddress : Address
    {
        public int PostalCode { get; set; }
        public string TownName { get; set; } = "";
        public string FullPostalAddress => PostalCode.ToString() + " " + TownName; 

        public override string ToString() => base.ToString() + " " + FullPostalAddress;
    }
}
