namespace jnUtilTests;


[TestClass]
public class SecureRandomTests
{
    [TestMethod]
    public void DoubleTests()
    {
        // Arrange
        double[] ds = new double[1000000];

        // Act
        ds = SecureRandom.Doubles(ds.Length);
        bool test = true;
        for (int i = 0; i < ds.Length; i++)
            if (ds[i] <0 || ds[i] > 1)
                test = false;

        // Assert
        Assert.IsTrue(test);
    }

    [TestMethod]
    public void DistributionTests()
    {
        // Arrange
        double sum = 0;
        int c = 0;

        // Act
        for (c = 0; c < 1000000; c++)
            sum += SecureRandom.Double;

        double mean = sum / (c + 1);

        // Assert
        Assert.IsTrue(mean > 0.499 && mean < 0.501);
    }

    [TestMethod]
    public void DieTests()
    {
        // Arrange
        int n = 1000000;
        byte sides = 6;
        bool test = true;

        // Act
        for (int i = 0; i < n; i++)
        {
            int dice_throw = SecureRandom.RollDice(sides);
            if(dice_throw < 1 || dice_throw > sides)
            {
                test = false;
                break;
            }
        }

        // Assert
        Assert.IsTrue(test);
    }
}
