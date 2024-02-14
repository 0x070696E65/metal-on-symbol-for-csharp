using System.Diagnostics;
using System.Text;
using MetalForSymbol.utils;
using Org.BouncyCastle.Crypto.Digests;
using Network = MetalForSymbol.models.Network;
using SymbolSdk;
using SymbolSdk.Symbol;
using Newtonsoft.Json;

public class SymbolService
{
    public Network? Network;
    public SymbolServiceConfig Config;
    public Func<string, Task<string>> HttpRequestMethod;

    public SymbolService(SymbolServiceConfig _symbolServiceConfig, Func<string, Task<string>> _httpRequestMethod)
    {
        Config = _symbolServiceConfig;
        Network = null;
        HttpRequestMethod = _httpRequestMethod;
    }
    
    public SymbolService(SymbolServiceConfig _symbolServiceConfig)
    {
        Config = _symbolServiceConfig;
        Network = null;
        HttpRequestMethod = HttpService.GetJsonAsync;
    }
    
    public void Init(Network network)
    {
        Network = network;
    }

    public async Task Init(bool isPrivate = false)
    {
        Network = await GetNetwork(isPrivate);
    }
    
    public string CalculateMetadataHash(
        MetadataType type,
        PublicKey sourcePublicKey,
        PublicKey targetPublicKey,
        ulong key,
        string? targetId = null
        ) {
        if (Network == null) throw new NullReferenceException("network is null");
        var sourceAddress = Converter.AddressToString(Network.Facade.Network.PublicKeyToAddress(sourcePublicKey.bytes).bytes);
        var targetAddress = Converter.AddressToString(Network.Facade.Network.PublicKeyToAddress(targetPublicKey.bytes).bytes);
        var hasher = new Sha3Digest(256);
        var add1 = Converter.StringToAddress(sourceAddress);
        var add2 = Converter.StringToAddress(targetAddress);
        hasher.BlockUpdate(add1, 0, add1.Length);
        hasher.BlockUpdate(add2, 0, add2.Length);
        var keyBytes = BitConverter.GetBytes(key);
        hasher.BlockUpdate(keyBytes, 0, keyBytes.Length);
        var targetIdBytes = Converter.HexToBytes(targetId ?? "0000000000000000");
        hasher.BlockUpdate(targetIdBytes, 0, targetIdBytes.Length);
        var typeByte = new byte[1] {(byte)type};
        hasher.BlockUpdate(typeByte, 0, typeByte.Length);
        var result = new byte[32];
        hasher.DoFinal(result, 0);
        return Converter.BytesToHex(result);
    }
    
    private async Task<Network?> GetNetwork(bool isPrivate = false)
    {
        var json = await HttpRequestMethod(Config.NodeUrl + "/network/properties");
        var n = JsonConvert.DeserializeObject<NetworkProperties.Root>(json);
        if (isPrivate)
        {
            var identifier = n?.network.identifier == "mainnet" ? (byte)0x68 : (byte)0x98;
            var unixTimeStamp = double.Parse(n?.network.epochAdjustment.TrimEnd('s'));
            var date = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(unixTimeStamp);
            return new Network(new SymbolSdk.Symbol.Network(n?.network.identifier, identifier, date, new Hash256(Converter.HexToBytes(n?.network.generationHashSeed))));
        }
        var networkType = n?.network.identifier switch
        {
            "mainnet" => SymbolSdk.Symbol.Network.MainNet,
            "testnet" => SymbolSdk.Symbol.Network.TestNet,
            _ => throw new Exception("network.identifier is invalid")
        };
        
        return new Network(networkType);
    }
    
    public IBaseTransaction CreateMetadataTx(
        PublicKey sourcePubKey,
        PublicKey targetPubKey,
        ulong key,
        byte[] value,
        ushort valueSizeDelta
    )
    {
        if (Network == null) throw new NullReferenceException("network is null");
        var add = Network.Facade.Network.PublicKeyToAddress(targetPubKey.bytes);
        return new EmbeddedAccountMetadataTransactionV1
        {
            Network = Network.NetworkTypeForTx,
            SignerPublicKey = sourcePubKey,
            TargetAddress = new UnresolvedAddress(add.bytes),
            ScopedMetadataKey = key,
            ValueSizeDelta = valueSizeDelta,
            Value = value
        };

    }

    private AggregateCompleteTransactionV2 ComposeAggregateCompleteTx(
        IBaseTransaction[] txs,
        PublicKey signerPubKey
    ) {
        var merkleHash = SymbolFacade.HashEmbeddedTransactions(txs);
        if (Network == null) throw new NullReferenceException("network is null");
        var aggregateTransaction = new AggregateCompleteTransactionV2
        {
            Network = Network.NetworkTypeForTx,
            Transactions = txs,
            SignerPublicKey = signerPubKey,
            TransactionsHash = merkleHash,
            Deadline = Network.Facade.Network.CreateDeadline(3600)
        };
        aggregateTransaction.Fee = new Amount((ulong)(aggregateTransaction.Size * Config.FeeRatio));
        return aggregateTransaction;
    }
    
    public List<AggregateCompleteTransactionV2> BuildAggregateCompleteTxBatches(
        List<IBaseTransaction> txs,
        PublicKey signerPublicKey,
        int batchSize = 100)
    {
        var txPool = txs.ToList();
        var batches = new List<AggregateCompleteTransactionV2>();

        while (txPool.Count > 0)
        {
            var innerTxs = txPool.Take(batchSize).ToArray();
            var aggregateTx = ComposeAggregateCompleteTx(
                innerTxs,
                signerPublicKey);

            batches.Add(aggregateTx);
            txPool.RemoveRange(0, innerTxs.Length);
        }

        return batches;
    }

    // Return: Array of signed aggregate complete TX and cosignatures (when cosigners are specified)
    public List<AggregateCompleteTransactionV2> BuildSignedAggregateCompleteTxBatches(
        List<IBaseTransaction> txs,
        KeyPair signerKeyPair,
        List<KeyPair>? cosignaturesKeyPair = null,
        int batchSize = 100)
    {
        var batches = BuildAggregateCompleteTxBatches(txs, signerKeyPair.PublicKey, batchSize);
        var signedTxList = new List<AggregateCompleteTransactionV2>();
        if(Network == null) throw new NullReferenceException("network is null");
        foreach (var batch in batches) {
            if (cosignaturesKeyPair != null)
            {
                const int sizePerCosignature = 8 + 32 + 64;
                var calculatedSize = batch.Size + cosignaturesKeyPair.Count * sizePerCosignature;
                batch.Fee = new Amount((ulong)(calculatedSize * Config.FeeRatio));
            }
            else
            {
                batch.Fee = new Amount(batch.Size * Config.FeeRatio);
            }
            var signature = Network.Facade.SignTransaction(signerKeyPair, batch);
            TransactionHelper.AttachSignature(batch, signature);
            
            if (cosignaturesKeyPair != null)
            {
                var cosignatures = 
                    (from cosignatureKeyPair in cosignaturesKeyPair 
                        let hash = Network.Facade.HashTransaction(batch) 
                        select new Cosignature {
                            Signature = cosignatureKeyPair.Sign(hash.bytes), 
                            SignerPublicKey = cosignatureKeyPair.PublicKey}).ToList();
                batch.Cosignatures = cosignatures.ToArray();
            }
            signedTxList.Add(batch);
        }
        return signedTxList;
    }
    
    public async Task<MetadataEntry> GetMetadataByHash(string compositeHash) {
        var url = $"{Config.NodeUrl}/metadata/{compositeHash}";
        var json = await HttpRequestMethod(url);
        var metadata = JsonConvert.DeserializeObject<Metadata>(json);
        if (metadata != null) return metadata.metadataEntry;
        throw new NullReferenceException("metadata is null");
    }
    
    public static string CreatePayload(AggregateCompleteTransactionV2 tx)
    {
        var transactionBuffer = tx.Serialize();
        var hexPayload = Converter.BytesToHex(transactionBuffer);
        return "{\"payload\": \"" + hexPayload + "\"}";
    }

    public async Task<string> ExecuteBatches(List<AggregateCompleteTransactionV2> batches)
    {
        var workers = batches.Select(CreatePayload)
            .Select(payload => Task.Run(async () =>
            {
                using var client = new HttpClient();
                var content = new StringContent(payload, Encoding.UTF8, "application/json");
                var res = await client.PutAsync(Config.NodeUrl + "/transactions", content);
            }))
            .ToList();
        try
        {
            await Task.WhenAll(workers);
            return "Complete";
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
        finally
        {
            foreach (var work in workers)
            {
                work.Dispose();
            }
        }
    }
    
    public async Task<List<Metadata>> SearchMetadataWithKey(AccountMetadataCriteria criteria)
    {
        var metadataPool = new List<Metadata>();
        var scopedMetadataKey = criteria.Key;
        MetalServiceV2.Magic magic = MetalServiceV2.Magic.CHUNK;
        while (true)
        {
            var sourceAddress = Converter.AddressToString(Converter.HexToBytes(criteria.SourceAddress));
            var targetAddress = Converter.AddressToString(Converter.HexToBytes(criteria.TargetAddress));
            var url = $"{Config.NodeUrl}/metadata?sourceAddress={sourceAddress}&targetAddress={targetAddress}&scopedMetadataKey={scopedMetadataKey}";
            var json = await HttpRequestMethod(url);
            var root = JsonConvert.DeserializeObject<Root>(json);
            Debug.Assert(root != null, nameof(root) + " != null");
            if (root.data.Count == 0) break;
            var raw = Converter.HexToUtf8(root.data[0].metadataEntry.value);
            var version = raw.Substring(1, 3);
            var _magic = raw[..1];
            if (version == "010")
            {
                magic = _magic == "E" ? MetalServiceV2.Magic.END_CHUNK : MetalServiceV2.Magic.CHUNK;
                scopedMetadataKey = raw.Substring(8, 16);
                metadataPool.AddRange(root.data ?? throw new InvalidOperationException());
            }
            else
            {
                var rawBin = Converter.HexToBytes(root.data[0].metadataEntry.value);
                magic = rawBin[0] != 0 ? MetalServiceV2.Magic.END_CHUNK : MetalServiceV2.Magic.CHUNK;
                var _meta = rawBin.ToList().GetRange(4, 8);
                scopedMetadataKey = Converter.BytesToHex(_meta.ToArray());
                metadataPool.AddRange(root.data ?? throw new InvalidOperationException());
            }
            if (magic == MetalServiceV2.Magic.END_CHUNK) break;
        }
        return metadataPool;
    }

    public async Task<List<Metadata>> SearchAccountMetadata(AccountMetadataCriteria criteria)
    {
        var count = 1;
        var metadataPool = new List<Metadata>();
        while (true)
        {
            var sourceAddress = Converter.AddressToString(Converter.HexToBytes(criteria.SourceAddress));
            var targetAddress = Converter.AddressToString(Converter.HexToBytes(criteria.TargetAddress));
            var url = $"{Config.NodeUrl}/metadata?sourceAddress={sourceAddress}&targetAddress={targetAddress}&pageNumber={count}";
            var json = await HttpRequestMethod(url);
            var root = JsonConvert.DeserializeObject<Root>(json);
            Debug.Assert(root != null, nameof(root) + " != null");
            if (root != null && root.data.Count == 0) break;
            if (root != null) metadataPool.AddRange(root.data ?? throw new InvalidOperationException());
            count++;
        }
        return metadataPool;
    }
}

public class SymbolServiceConfig
{
    public string NodeUrl;
    public byte FeeRatio;
    public byte DeadlineHours;
    public byte BatchSize;
    public byte MaxParallels;

    public SymbolServiceConfig(string _nodeUrl, byte _feeRatio = 100, byte _deadlineHours = 2, byte _batchSize = 100, byte _maxParallels = 10)
    {
        NodeUrl = _nodeUrl;
        FeeRatio = _feeRatio;
        DeadlineHours = _deadlineHours;
        BatchSize = _batchSize;
        MaxParallels = _maxParallels;
    }
}
public class AccountMetadataCriteria
{
    public string SourceAddress;
    public string TargetAddress;
    public string? Key;

    public AccountMetadataCriteria(string _sourceAddress, string _targetAddress, string? _key = null)
    {
        SourceAddress = _sourceAddress;
        TargetAddress = _targetAddress;
        Key = _key;
    }
}
