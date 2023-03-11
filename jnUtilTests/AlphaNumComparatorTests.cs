namespace jnUtilTests;

[TestClass]
public class AlphaNumComparatorTests
{
    [TestMethod]
    public void AlphaNumSortTest()
    {
        // Arrange
        List<string> ss = new string[] {"item20", "item19", "item1", "item10", "item2"}.ToList();
        List<string> ss2 = new string[] { "item1", "item2", "item10", "item19", "item20" }.ToList();

        // Act
        ss.Sort(new AlphaNumComparator());

        // Assert
        CollectionAssert.AreEqual(ss2, ss);
    }
}
