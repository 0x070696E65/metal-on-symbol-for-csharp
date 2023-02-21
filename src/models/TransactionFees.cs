namespace MetalForSymbol.models;

public class TransactionFees
{
    public int averageFeeMultiplier;
    public int medianFeeMultiplier;
    public int highestFeeMultiplier;
    public int lowestFeeMultiplier;
    public int minFeeMultiplier;

    public TransactionFees(int _averageFeeMultiplier, int _medianFeeMultiplier, int _highestFeeMultiplier, int _lowestFeeMultiplier, int _minFeeMultiplier)
    {
        averageFeeMultiplier = _averageFeeMultiplier;
        medianFeeMultiplier = _medianFeeMultiplier;
        highestFeeMultiplier = _highestFeeMultiplier;
        lowestFeeMultiplier = _lowestFeeMultiplier;
        minFeeMultiplier = _minFeeMultiplier;
    }
}