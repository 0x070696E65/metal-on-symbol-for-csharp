public class NetworkProperties
{
    public class Root
    {
        public Network network { get; set; } = null!;
    }
    
    public class Network
    {
        public string identifier { get; set; } = null!;
        public string generationHashSeed { get; set; } = null!;
        public string epochAdjustment { get; set; } = null!;
    }
}