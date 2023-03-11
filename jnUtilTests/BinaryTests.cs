namespace jnUtilTests;

[TestClass]
public class BinaryTests
{
    [TestMethod]
    public void ToFromBitArray()
    {
        // Arrange
        string bstring = "100100110";


        // Act
        BitArray bits = Binary.ToBitArray(bstring);
        byte[] bytes = Binary.ToByteArray(bits);
        string res1 = Binary.ToBitString(bits);
        string res2 = Binary.ToBinaryString(bytes, true, false, true);


        // Assert
        Assert.AreEqual(bstring,res1);
        Assert.AreEqual(bstring, res2);
    }
}
