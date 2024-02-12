

using SymbolSdk.Symbol;

namespace MetalForSymbol.models;

public class Network
{
    public SymbolSdk.Symbol.Network NetworkType;
    public NetworkType NetworkTypeForTx;
    public TransactionFees? TransactionFees;
    public SymbolFacade Facade;

    public Network(SymbolSdk.Symbol.Network _networkType)
    {
        NetworkType = _networkType;
        NetworkTypeForTx = _networkType == SymbolSdk.Symbol.Network.MainNet ? SymbolSdk.Symbol.NetworkType.MAINNET : SymbolSdk.Symbol.NetworkType.TESTNET;
        Facade = new SymbolFacade(NetworkType);
    }
}