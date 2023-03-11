using jnUtil.Entities;

namespace jnutilTests;

[TestClass]
public class AddressTests
{
    [TestMethod]
    public void ParseAddressTest()
    {
        // Arrange
        string address1 = "Main Street 21A";
        string address2 = "Main Street 21A 1001";
        string address3 = "Small Town Street 1";
        string address4 = "Small Town Street 1AB UV 1001";

        // Act
        Address a1 = Address.SplitAddress(address1);
        Address a2 = Address.SplitAddress(address2);
        Address a3 = Address.SplitAddress(address3);
        Address a4 = Address.SplitAddress(address4);

        string parsed_address1 = a1.FullAddress;
        string parsed_address2 = a2.FullAddress;
        string parsed_address3 = a3.FullAddress;
        string parsed_address4 = a4.FullAddress;


        // Assert
        Assert.AreEqual(address1, parsed_address1);
        Assert.AreEqual(address1, parsed_address1);
        Assert.AreEqual(address1, parsed_address1);
        Assert.AreEqual(address1, parsed_address1);
    }

    [TestMethod]
    public void ParseAddressPlaceTests()
    {
        // Arrange
        string address_place1 = "21A";
        string address_place2 = "1AB U1";

        // Act
        string number1 = Address.GetNumber(address_place1);
        string letter1 = Address.GetLetter(address_place1);
        string entrance1 = Address.GetEntrance(address_place1);

        string number2 = Address.GetNumber(address_place2);
        string letter2 = Address.GetLetter(address_place2);
        string entrance2 = Address.GetEntrance(address_place2);



        // Assert
        Assert.AreEqual("21", number1);
        Assert.AreEqual("A", letter1);
        Assert.AreEqual("", entrance1);
        Assert.AreEqual("1", number2);
        Assert.AreEqual("AB", letter2);
        Assert.AreEqual("U1", entrance2);
    }
}
