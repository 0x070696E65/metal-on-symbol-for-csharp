using System.Diagnostics;
using System.Globalization;
using System.Text;
using SymbolSdk;
using SymbolSdk.Symbol;
using MetalForSymbol.utils;
using Org.BouncyCastle.Utilities.Encoders;

public class MetalServiceV2
{
    public enum Magic {
        CHUNK = 0x00,
        END_CHUNK = 0x80,
    }
    
    private const short DEFAULT_ADDITIVE = 0;
    private const short VERSION = 0x31;
    private const int HEADER_SIZE = 12;
    private const int CHUNK_PAYLOAD_MAX_SIZE = 1012;
    private const string METAL_ID_HEADER_HEX = "0B2A";
    
    private static bool IsMagic(byte value)
    {
        return value is (byte)Magic.CHUNK or (byte)Magic.END_CHUNK;
    }
    
    // Use sha3_256 of first 64 bits, MSB should be 0
    public static ulong GenerateMetadataKey(string input)
    {
        return MetalService.GenerateMetadataKey(input);
    }
    public static ulong GenerateMetadataKey(byte[] input)
    {
        return MetalService.GenerateMetadataKey(input);
    }
    
    // Use sha3_256 of first 64 bits
    private static ulong GenerateChecksum(byte[] input) {
        return MetalService.GenerateChecksum(input);
    }

    // Return 64 bytes hex string
    public static string RestoreMetadataHash(string metalId)
    {
        return MetalService.RestoreMetadataHash(metalId);
    }
    
    // Return 46 bytes base58 string
    public string CalculateMetalId(
        MetadataType type, 
        PublicKey sourcePublicKey,
        PublicKey targetPublicKey,
        ulong key,
        string? targetId = null
    ) {
        var compositeHash = SymbolService.CalculateMetadataHash(
            type,
            sourcePublicKey,
            targetPublicKey,
            key,
            targetId
        );
        var hashBytes = Converter.HexToBytes(METAL_ID_HEADER_HEX + compositeHash);
        return Base58Encoding.Encode(hashBytes);
    }

    private static short GenerateRandomAdditive() {
        var random = new Random();
        var randomValue = random.NextDouble();
        return (short) Math.Floor(randomValue * 0xFFFF);
    }
    
    private static Dictionary<string, Metadata> CreateMetadataLookupTable(IEnumerable<Metadata>? metadataPool = null)
    {
        var lookupTable = new Dictionary<string, Metadata>();
        metadataPool?.ToList().ForEach(metadata =>
            lookupTable[metadata.metadataEntry.scopedMetadataKey] = metadata);
        return lookupTable;
    }
    
    private static (byte[] Value, ulong Key) PackChunkBytes(
        Magic magic,
        short version,
        short additive,
        ulong nextKey, 
        byte[] chunkBytes
    )
    {
        // Append next scoped key into chunk's tail (except end of line)
        var value = new byte[chunkBytes.Length + HEADER_SIZE];
        Debug.Assert(value.Length <= 1024);

        // Header (12 bytes)
        value[0] = (byte)((byte)magic & 0x80);
        value[1] = (byte)((byte)version & 0xFF);
        Array.Copy(BitConverter.GetBytes(additive).Reverse().ToArray(), 0, value, 2, 2);
        Array.Copy(BitConverter.GetBytes(nextKey).Reverse().ToArray(), 0, value, 4, 8);
        
        // Payload (max 1012 bytes)
        Array.Copy(chunkBytes, 0, value, HEADER_SIZE, chunkBytes.Length);
        
        var key = GenerateMetadataKey(value);
        return (value, key);
    }
    
    public static ulong CalculateMetadataKey(byte[] payload, short additive = DEFAULT_ADDITIVE)
    {
        var chunks = (int)Math.Ceiling((double)payload.Length / CHUNK_PAYLOAD_MAX_SIZE);
        var nextKey = GenerateChecksum(payload);
        for (var i = chunks - 1; i >= 0; i--)
        {
            var magic = i == chunks - 1 ? Magic.END_CHUNK : Magic.CHUNK;
            var chunkBytes = payload.Skip(i * CHUNK_PAYLOAD_MAX_SIZE).Take(CHUNK_PAYLOAD_MAX_SIZE).ToArray();
            var result = PackChunkBytes(magic, VERSION, additive, nextKey, chunkBytes);
            nextKey = result.Key;
        }
        return nextKey;
    }
    
    // Verify metadata key with calculated one. "additive" must be specified when using non-default one.
    public static bool VerifyMetadataKey (
        ulong key,
        byte[] payload, 
        short additive = DEFAULT_ADDITIVE
    ) {
        return CalculateMetadataKey(payload, additive).Equals(key);   
    }
    
    public static (Magic magic, byte version, ulong checksum, ulong nextKey, byte[] chunkPayload, short additive)? ExtractChunk(MetadataEntry chunk)
    {
        var chunkValue = Converter.HexToBytes(chunk.value);
        var magic = (byte)(chunkValue[0] & 0x80) == (byte)Magic.END_CHUNK ? Magic.END_CHUNK : Magic.CHUNK;
        var version = chunkValue[1];
        if (version != VERSION)
        {
            var result = MetalService.ExtractChunk(chunk);
            if(result == null) throw new Exception("Error: V1 chunk is something brokern.");
            var _magic = result.Value.magic == "E" ? Magic.END_CHUNK : Magic.CHUNK;
            var _additive = BitConverter.ToInt16(result.Value.additive);
            var _checkSum = ulong.Parse(result.Value.checksum, NumberStyles.HexNumber);
            var _chunkPayload = Base64.Decode(result.Value.chunkPayload);
            return (_magic, version, _checkSum, result.Value.nextKey, _chunkPayload, _additive);
        }
        
        var checksum = GenerateMetadataKey(chunkValue);
        if (!checksum.Equals(ulong.Parse(chunk.scopedMetadataKey, NumberStyles.HexNumber)))
        {
            Console.WriteLine($"Error: The chunk {chunk.scopedMetadataKey} is broken (calculated={checksum})");
            return null;
        }
        var addr = chunkValue.ToList().GetRange(2, 2).ToArray();
        var additive = BitConverter.ToInt16(addr.Reverse().ToArray(), 0);
        var keyr = chunkValue.ToList().GetRange(4, 8).ToArray();
        var nextKey = BitConverter.ToUInt64(keyr.Reverse().ToArray());
        var chunkPayload = chunkValue.ToList().GetRange(HEADER_SIZE, chunkValue.Length - HEADER_SIZE).ToArray();
        
        return (magic, version, checksum, nextKey, chunkPayload, additive);
    }
    
    public static byte[] Decode(string currentKeyHex, IEnumerable<Metadata> metadataPool)
    {
        var lookupTable = CreateMetadataLookupTable(metadataPool);
        var decodedBytes = new List<byte>{};
        byte? version = null;
        Magic magic;
        do
        {
            if (!lookupTable.Remove(currentKeyHex, out var metadata)) {
                throw new Exception($"Error: The chunk {currentKeyHex} lost");
            }

            // Prevent loop
            var result = ExtractChunk(metadata.metadataEntry);
            if (result == null) {
                break;
            }

            version = result.Value.version;
            magic = result.Value.magic;
            currentKeyHex = result.Value.nextKey.ToString("X16");
            decodedBytes.AddRange(result.Value.chunkPayload);
        } while (magic != Magic.END_CHUNK);
        if(version != null || version == VERSION) {
            return decodedBytes.ToArray();
        }
        return Base64.Decode(Converter.BytesToHex(decodedBytes.ToArray()));
    }
    
    private SymbolService SymbolService;

    public MetalServiceV2(SymbolService _symbolService)
    {
        SymbolService = _symbolService;
    }
    
    // Returns:
    // - key: Metadata key of first chunk (undefined when no transactions were created)
    // - txs: List of metadata transaction (InnerTransaction for aggregate tx)
    // - additive: Actual additive that been used during encoding. You should store this for verifying the metal.
    public async Task<(ulong Key, List<IBaseTransaction> Txs, short? Additive)> CreateForgeTxs(
        PublicKey sourcePubKey,
        PublicKey targetPubKey,
        byte[] payload,
        short? additive = null,
        Metadata[]? metadataPool = null)
    {
        additive ??= DEFAULT_ADDITIVE;
        var lookupTable = CreateMetadataLookupTable(metadataPool);
        var txs = new List<IBaseTransaction>();
        var keys = new List<string>();
        var chunks = (int) Math.Ceiling((double) payload.Length / CHUNK_PAYLOAD_MAX_SIZE);
        var nextKey = GenerateChecksum(payload);

        for (var i = chunks - 1; i >= 0; i--)
        {
            var magic = i == chunks - 1 ? Magic.END_CHUNK : Magic.CHUNK;
            var chunkBytes = payload.Skip(i * CHUNK_PAYLOAD_MAX_SIZE).Take(CHUNK_PAYLOAD_MAX_SIZE).ToArray();

            var (value, key) = PackChunkBytes(magic, VERSION, (short) additive, nextKey, chunkBytes);

            if (keys.Contains(key.ToString("X16")))
            {
                Console.WriteLine($"Warning: Scoped key \"{key.ToString("X16")}\" has been conflicted. Trying another additive.");
                // Retry with another additive via recursive call
                return await CreateForgeTxs(
                    sourcePubKey,
                    targetPubKey,
                    payload,
                    GenerateRandomAdditive(),
                    metadataPool);
            }

            // Only non on-chain data to be announced.
            if (!lookupTable.ContainsKey(key.ToString("X16")))
            {
                txs.Add(SymbolService.CreateMetadataTx(
                    sourcePubKey,
                    targetPubKey,
                    key,
                    value,
                    (ushort)value.Length));
            }

            keys.Add(key.ToString("X16"));
            nextKey = key;
        }
        txs.Reverse();
        return (nextKey, txs, additive);
    }
    
    // Scrap metal via removing metadata
    public async Task<List<IBaseTransaction>?>? CreateScrapTxs(
        MetadataType type,
        PublicKey sourcePubKey,
        PublicKey targetPubKey,
        ulong key,
        List<Metadata>? metadataPool = null
    )
    {
        if (SymbolService.Network == null) throw new NullReferenceException("network is null");
        var sourceAddress = Converter.BytesToHex(SymbolService.Network.Facade.Network.PublicKeyToAddress(sourcePubKey.bytes).bytes);
        var targetAddress = Converter.BytesToHex(SymbolService.Network.Facade.Network.PublicKeyToAddress(targetPubKey.bytes).bytes);
        var lookupTable = CreateMetadataLookupTable(
            metadataPool ?? 
            // Retrieve scoped metadata from on-chain
            await SymbolService.SearchAccountMetadata( 
                new AccountMetadataCriteria(
                sourceAddress,
                targetAddress,
                key.ToString("X16")))
        );
        var scrappedValueBytes = Converter.Utf8ToBytes("");
        var txs = new List<IBaseTransaction>();
        var currentKeyHex = key.ToString("X16");
        Magic magic;
        
        do
        {
            if (!lookupTable.Remove(currentKeyHex, out var metadata))
            {
                Console.WriteLine($"Error: The chunk {currentKeyHex} lost.");
                return null;
            }

            // Prevent loop
            var chunk = ExtractChunk(metadata.metadataEntry);
            if (chunk == null)
            {
                return null;
            }

            var valueBytes = Converter.HexToBytes(metadata.metadataEntry.value);
            txs.Add(SymbolService.CreateMetadataTx(
                sourcePubKey,
                targetPubKey,
                ulong.Parse(metadata.metadataEntry.scopedMetadataKey, NumberStyles.HexNumber),
                Converter.Xor(valueBytes, scrappedValueBytes),
                (ushort)(scrappedValueBytes.Length - valueBytes.Length)
            ));

            magic = chunk.Value.magic;
            currentKeyHex = chunk.Value.nextKey.ToString("X16");
        } while (magic != Magic.END_CHUNK);
        return txs;
    }

    public async Task<IEnumerable<IBaseTransaction>> CreateDestroyTxs(
        MetadataType type,
        PublicKey sourcePubKey,
        PublicKey targetPubKey,
        MosaicId targetId,
        byte[] payload,
        short? additive = null,
        Metadata[]? metadataPool = null
    )
    {
        additive ??= DEFAULT_ADDITIVE;
        if (SymbolService.Network == null) throw new NullReferenceException("network is null");
        var sourceAddress = Converter.AddressToString(SymbolService.Network.Facade.Network.PublicKeyToAddress(sourcePubKey.bytes).bytes);
        var targetAddress = Converter.AddressToString(SymbolService.Network.Facade.Network.PublicKeyToAddress(targetPubKey.bytes).bytes);
        var lookupTable = CreateMetadataLookupTable(
            metadataPool ??
            (await SymbolService.SearchAccountMetadata(
                new AccountMetadataCriteria(
                    sourceAddress,
                    targetAddress))).ToArray()
        );
        var scrappedValueBytes = Encoding.UTF8.GetBytes("");
        var payloadBase64Bytes = Encoding.UTF8.GetBytes(Convert.ToBase64String(payload));
        var chunks = (int) Math.Ceiling(payloadBase64Bytes.Length / (double) CHUNK_PAYLOAD_MAX_SIZE);
        var txs = new List<IBaseTransaction>();
        var nextKey = GenerateChecksum(payload);
        
        for (var i = chunks - 1; i >= 0; i--)
        {
            var magic = i == chunks - 1 ? Magic.END_CHUNK : Magic.CHUNK;
            var chunkBytes = payloadBase64Bytes.Skip(i * CHUNK_PAYLOAD_MAX_SIZE).Take(CHUNK_PAYLOAD_MAX_SIZE).ToArray();
            var packedChunk = PackChunkBytes(magic, VERSION, (short)additive, nextKey, chunkBytes);
            var key = packedChunk.Key;

            lookupTable.TryGetValue(key.ToString("X26"), out var onChainMetadata);
            if (onChainMetadata != null)
            {
                // Only on-chain data to be announced.
                var valueBytes = Encoding.UTF8.GetBytes(onChainMetadata.metadataEntry.value);
                var xorValue = Converter.Xor(valueBytes, scrappedValueBytes);
                var metadataTx = SymbolService.CreateMetadataTx(
                    sourcePubKey,
                    targetPubKey,
                    key,
                    xorValue,
                    (ushort)(scrappedValueBytes.Length - valueBytes.Length)
                );
                txs.Add(metadataTx);
            }

            nextKey = key;
        }

        return txs.AsEnumerable().Reverse();
    }

    public async Task<List<ulong>> CheckCollision(
        IBaseTransaction[] txs,
        string source,
        string target,
        Metadata[]? metadataPool = null)
    {
        var lookupTable = CreateMetadataLookupTable(
            metadataPool ??
            // Retrieve scoped metadata from on-chain
            (await SymbolService.SearchAccountMetadata(new AccountMetadataCriteria(source, target))).ToArray()
        );
        var collisions = new List<ulong>();

        var metadataTxTypes = new [] {
            typeof(AccountMetadataTransactionV1),
        };

        foreach (var tx in txs)
        {
            if (!metadataTxTypes.Contains(tx.GetType()))
            {
                continue;
            }
            var metadataTx = tx as AccountMetadataTransactionV1;
            var keyHex = metadataTx?.ScopedMetadataKey.ToString("X16");
            if (keyHex != null && lookupTable.ContainsKey(keyHex))
            {
                Console.WriteLine($"{keyHex}: Already exists on the chain.");
                if (metadataTx != null) collisions.Add(metadataTx.ScopedMetadataKey);
            }
        }

        return collisions;
    }
    
    public async Task<(int maxLength, int mismatches)> Verify(
        byte[] payload,
        string sourceAddress,
        string targetAddress,
        string key,
        List<Metadata>? metadataPool = null)
    {
        var payloadBase64 = Base64.Encode(payload);
        var decodedBase64 = Decode(
            key,
            metadataPool ??
            await SymbolService.SearchAccountMetadata(new AccountMetadataCriteria(sourceAddress, targetAddress)
            {
                SourceAddress = sourceAddress,
                TargetAddress = targetAddress
            }));

        var mismatches = 0;
        var maxLength = Math.Max(payloadBase64.Length, decodedBase64.Length);

        for (var i = 0; i < maxLength; i++)
        {
            if (payloadBase64[i] != decodedBase64.ElementAtOrDefault(i))
            {
                mismatches++;
            }
        }

        return (maxLength, mismatches);
    }
    
    public async Task<MetadataEntry> GetFirstChunk(string metalId) {
        return await SymbolService.GetMetadataByHash(RestoreMetadataHash(metalId));
    }

    public async Task<byte[]> Fetch(
        string source,
        string target,
        string key,
        bool isKey = false
    ) {
        var metadataPool = isKey ? await SymbolService.SearchMetadataWithKey(new AccountMetadataCriteria(source, target, key)) : await SymbolService.SearchAccountMetadata(new AccountMetadataCriteria(source, target));
        return Decode(key, metadataPool);
    }
    
    // Returns:
    //   - payload: Decoded metal contents
    //   - sourceAddress: Metadata source address
    //   - targetAddress: Metadata target address
    //   - key: Metadata key
    public async Task<(byte[] Payload, string SourceAddress, string TargetAddress, string Key)> FetchByMetalId(string metalId, bool isKey = false) {
        var metadataEntry = await GetFirstChunk(metalId);
        var payload = await Fetch(
            metadataEntry.sourceAddress,
            metadataEntry.targetAddress,
            metadataEntry.scopedMetadataKey,
            isKey
        );
        return (payload, metadataEntry.sourceAddress, metadataEntry.targetAddress, metadataEntry.scopedMetadataKey);
    }
    
    private static string To36(int value)
    {
        const string base36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        var result = "";

        while (value > 0) {
            var remainder = value % 36;
            result = base36[remainder] + result;
            value /= 36;
        }

        if (result == "") {
            result = "0";
        }
        return result;
    }
}