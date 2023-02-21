using CatSdk.Facade;
using CatSdk.Symbol;

namespace MetalForSymbol.models;

public class Network
{
    public CatSdk.Symbol.Network NetworkType;
    public NetworkType NetworkTypeForTx;
    public TransactionFees? TransactionFees;
    public SymbolFacade Facade;

    public Network(CatSdk.Symbol.Network _networkType, TransactionFees _transactionFees)
    {
        NetworkType = _networkType;
        NetworkTypeForTx = _networkType == CatSdk.Symbol.Network.MainNet ? CatSdk.Symbol.NetworkType.MAINNET : CatSdk.Symbol.NetworkType.TESTNET;
        TransactionFees = _transactionFees;
        Facade = new SymbolFacade(NetworkType);
    }
}