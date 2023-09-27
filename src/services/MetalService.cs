using System.Diagnostics;
using System.Globalization;
using System.Text;
using CatSdk.Symbol;
using CatSdk.Utils;
using MetalForSymbol.models;
using MetalForSymbol.utils;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;

public enum Magic {
    CHUNK,
    END_CHUNK,
}

public class MetalService
{
    private const string VERSION = "010";
    private const int HEADER_SIZE = 24;
    private const int CHUNK_PAYLOAD_MAX_SIZE = 1000;
    private const string METAL_ID_HEADER_HEX = "0B2A";
    
    private static bool IsMagic(string c)
    {
        return c switch {
            "C" => true,
            "E" => true,
            _ => throw new Exception("invalid magic type")
        };
    }

    private static byte[] DEFAULT_ADDITIVE = Converter.Utf8ToBytes("0000");
    
    // Use sha3_256 of first 64 bits, MSB should be 0
    public static ulong GenerateMetadataKey(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        
        var sha3256Digest = new Sha3Digest(256);
        var sha3256Hash = new byte[sha3256Digest.GetDigestSize()];
        sha3256Digest.BlockUpdate(bytes, 0, bytes.Length);
        sha3256Digest.DoFinal(sha3256Hash, 0);
        var uintArray = sha3256Hash.Select((x, i) => new { Index = i / 4, Value = x })
            .GroupBy(x => x.Index, x => x.Value)
            .Select(x => BitConverter.ToUInt32(x.ToArray(), 0))
            .ToArray();
        return (ulong)((uintArray[1] & 0x7FFFFFFF) * 0x100000000 + uintArray[0]);
    }
    
    // Use sha3_256 of first 64 bits
    private static ulong GenerateChecksum(byte[] input) {
        if (input.Length == 0) {
            throw new Exception("Input must not be empty");
        }
        var sha3256Digest = new Sha3Digest(256);
        var sha3256Hash = new byte[sha3256Digest.GetDigestSize()];
        sha3256Digest.BlockUpdate(input, 0, input.Length);
        sha3256Digest.DoFinal(sha3256Hash, 0);
        var list = new List<byte>(sha3256Hash).GetRange(0, 8);
        return BitConverter.ToUInt64(list.ToArray(), 0);
    }

    private static byte[] GenerateRandomAdditive() {
        var random = new Random();
        var randomValue = random.NextDouble();
        var array = Converter.Utf8ToBytes("000" + To36((int) Math.Floor(randomValue * 1679616)));
        var lastFour = new byte[4];
        Array.Copy(array, array.Length - 4, lastFour, 0, 4);
        return lastFour.ToArray();
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
    
    // Return 64 bytes hex string
    public static string RestoreMetadataHash(string metalId) {
        var hashHex = Converter.BytesToHex(
            Base58Encoding.Decode(metalId)
        );
        if (!hashHex.StartsWith(METAL_ID_HEADER_HEX)) {
            throw new Exception("Invalid metal ID.");
        }
        return hashHex.Substring(METAL_ID_HEADER_HEX.Length);
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
        string version, 
        byte[]? additive,
        ulong nextKey, 
        byte[] chunkBytes
    )
    {
        Debug.Assert(additive is {Length: >= 4});
        
        // Append next scoped key into chunk's tail (except end of line)
        var value = new byte[chunkBytes.Length + 8 + (nextKey != 0 ? 16 : 0)];
        Debug.Assert(value.Length <= 1024);
        
        var m = magic switch {
            Magic.CHUNK => "C",
            Magic.END_CHUNK => "E",
            _ => throw new Exception("invalid magic type")
        };
        // Header (24 bytes)
        value[0] = Converter.Utf8ToBytes(m)[0];
        Array.Copy(Converter.Utf8ToBytes(version.Substring(0,3)), 0, value, 1, 3);
        Array.Copy(additive, 0, value, 4, 4);
        Array.Copy(Converter.Utf8ToBytes(nextKey.ToString("X16")), 0, value, 8, 16);
        
        // Payload (max 1000 bytes)
        Array.Copy(chunkBytes, 0, value, HEADER_SIZE, chunkBytes.Length);
        
        var key = GenerateMetadataKey(Encoding.UTF8.GetString(value));
        return (value, key);
    }
    
    public static ulong CalculateMetadataKey(byte[] payload, byte[]? additive = null)
    {
        additive ??= DEFAULT_ADDITIVE;
        var payloadBase64Bytes = Converter.Utf8ToBytes(Convert.ToBase64String(payload));

        var chunks = (int)Math.Ceiling((double)payloadBase64Bytes.Length / CHUNK_PAYLOAD_MAX_SIZE);
        var nextKey = GenerateChecksum(payload);
        for (var i = chunks - 1; i >= 0; i--)
        {
            var magic = i == chunks - 1 ? Magic.END_CHUNK : Magic.CHUNK;
            var chunkBytes = payloadBase64Bytes.Skip(i * CHUNK_PAYLOAD_MAX_SIZE).Take(CHUNK_PAYLOAD_MAX_SIZE).ToArray();
            var result = PackChunkBytes(magic, VERSION, additive, nextKey, chunkBytes);
            nextKey = result.Key;
        }
        return nextKey;
    }
    
    // Verify metadata key with calculated one. "additive" must be specified when using non-default one.
    public static bool VerifyMetadataKey (
        ulong key,
        byte[] payload, 
        byte[]? additive = null
    ) {
        additive ??= DEFAULT_ADDITIVE;
        return CalculateMetadataKey(payload, additive).Equals(key);   
    }
    
    public static (string magic, string version, string checksum, byte[] nextKey, byte[] chunkPayload, byte[] additive)? ExtractChunkBytes(MetadataEntry chunk)
    {
        var magic = Converter.HexToUtf8(chunk.value.Substring(0, 2));
        if (!IsMagic(magic))
        {
            Console.WriteLine($"Error: Malformed header magic {magic}");
            return null;
        }
        var version = Converter.HexToUtf8(chunk.value.Substring(2, 6));
        if (version != VERSION)
        {
            Console.WriteLine($"Error: Malformed header version {version}");
            return null;
        }
        
        var metadataValue = Converter.HexToBytes(chunk.value);
        var checksum = GenerateMetadataKey(Converter.HexToUtf8(chunk.value)).ToString("X16");
        if (!checksum.Equals(chunk.scopedMetadataKey))
        {
            Console.WriteLine($"Error: The chunk {chunk.scopedMetadataKey} is broken (calculated={checksum})");
            return null;
        }
        var additive = new byte[4];
        Array.Copy(metadataValue, 4, additive, 0, 4);
        additive = Encoding.UTF8.GetBytes(Converter.BytesToHex(additive));
        var nextKey = new byte[16];
        Array.Copy(metadataValue, 8, nextKey, 0, 16);
        var chunkPayload = metadataValue.Length != HEADER_SIZE + CHUNK_PAYLOAD_MAX_SIZE
            ? metadataValue.Skip(HEADER_SIZE).ToArray()
            : metadataValue.Skip(HEADER_SIZE).Take(CHUNK_PAYLOAD_MAX_SIZE).ToArray();

        return (magic, version, checksum, nextKey, chunkPayload, additive);
    }
    
    public static (string magic, string version, string checksum, ulong nextKey, string chunkPayload, byte[] additive)? ExtractChunk(MetadataEntry chunk)
    {
        var magic = Converter.HexToUtf8(chunk.value.Substring(0, 2));
        if (!IsMagic(magic))
        {
            Console.WriteLine($"Error: Malformed header magic {magic}");
            return null;
        }
        var version = Converter.HexToUtf8(chunk.value.Substring(2, 6));
        if (version != VERSION)
        {
            Console.WriteLine($"Error: Malformed header version {version}");
            return null;
        }
            
        var metadataValue = Converter.HexToUtf8(chunk.value);
        var checksum = GenerateMetadataKey(metadataValue).ToString("X16");
        if (!checksum.Equals(chunk.scopedMetadataKey))
        {
            Console.WriteLine($"Error: The chunk {Converter.HexToUtf8(chunk.scopedMetadataKey)} is broken (calculated={checksum})");
            return null;
        }
        var additive = Converter.Utf8ToBytes(metadataValue.Substring(4, 4));
        var nextKey = ulong.Parse(metadataValue.Substring(8, HEADER_SIZE - 8), NumberStyles.HexNumber);
        var chunkPayload = metadataValue.Length != HEADER_SIZE + CHUNK_PAYLOAD_MAX_SIZE
            ? metadataValue.Substring(HEADER_SIZE)
            : metadataValue.Substring(HEADER_SIZE, CHUNK_PAYLOAD_MAX_SIZE);

        return (magic, version, checksum, nextKey, chunkPayload, additive);
    }
    
    public static string Decode(string currentKeyHex, IEnumerable<Metadata> metadataPool)
    {
        var lookupTable = CreateMetadataLookupTable(metadataPool);

        var decodedString = "";
        string magic;
        do
        {
            if (!lookupTable.TryGetValue(currentKeyHex, out var metadata)) {
                throw new Exception($"Error: The chunk {currentKeyHex} lost");
            }
            lookupTable.Remove(currentKeyHex);  // Prevent loop

            var result = ExtractChunk(metadata.metadataEntry);
            if (result == null) {
                break;
            }

            magic = result.Value.magic;
            currentKeyHex = result.Value.nextKey.ToString("X16");
            decodedString += result.Value.chunkPayload;
        } while (magic != "E");

        return decodedString;
    }
    
    public static byte[] DecodeBytes(string currentKeyHex, IEnumerable<Metadata> metadataPool)
    {
        var lookupTable = CreateMetadataLookupTable(metadataPool);
        var decoded = new List<byte>{};
        string magic;
        do
        {
            if (!lookupTable.TryGetValue(currentKeyHex, out var metadata)) {
                throw new Exception($"Error: The chunk {currentKeyHex} lost");
            }
            lookupTable.Remove(currentKeyHex);  // Prevent loop

            var result = ExtractChunkBytes(metadata.metadataEntry);
            if (result == null) {
                break;
            }

            magic = result.Value.magic;
            currentKeyHex = Encoding.UTF8.GetString(result.Value.nextKey);
            decoded.AddRange(result.Value.chunkPayload.ToList());
        } while (magic != "E");

        return decoded.ToArray();
    }

    private SymbolService SymbolService;

    public MetalService(SymbolService _symbolService)
    {
        SymbolService = _symbolService;
    }
    
    // Returns:
    // - key: Metadata key of first chunk (undefined when no transactions were created)
    // - txs: List of metadata transaction (InnerTransaction for aggregate tx)
    // - additive: Actual additive that been used during encoding. You should store this for verifying the metal.
    public async Task<(ulong Key, List<IBaseTransaction> Txs, byte[]? Additive)> CreateForgeTxs(
        PublicKey sourcePubKey,
        PublicKey targetPubKey,
        byte[] payload,
        bool isBytes = true,
        byte[]? additive = null,
        Metadata[]? metadataPool = null)
    {
        additive ??= DEFAULT_ADDITIVE;
        var lookupTable = CreateMetadataLookupTable(metadataPool);
        var payloadBytes = isBytes ? payload : Converter.Utf8ToBytes(Base64.ToBase64String(payload));
        var txs = new List<IBaseTransaction>();
        var keys = new List<string>();
        var chunks = (int) Math.Ceiling((double) payloadBytes.Length / CHUNK_PAYLOAD_MAX_SIZE);
        var nextKey = GenerateChecksum(payload);

        for (var i = chunks - 1; i >= 0; i--)
        {
            var magic = i == chunks - 1 ? Magic.END_CHUNK : Magic.CHUNK;
            var chunkBytes = payloadBytes.Skip(i * CHUNK_PAYLOAD_MAX_SIZE).Take(CHUNK_PAYLOAD_MAX_SIZE).ToArray();

            var (value, key) = PackChunkBytes(magic, VERSION, additive, nextKey, chunkBytes);

            if (keys.Contains(key.ToString("X16")))
            {
                Console.WriteLine($"Warning: Scoped key \"{key.ToString("X16")}\" has been conflicted. Trying another additive.");
                // Retry with another additive via recursive call
                return await CreateForgeTxs(
                    sourcePubKey,
                    targetPubKey,
                    payload,
                    isBytes,
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

            keys.Add(key.ToString("X26"));
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
        MosaicId targetId,
        ulong key,
        List<Metadata>? metadataPool = null
    )
    {
        if (SymbolService.Network == null) throw new NullReferenceException("network is null");
        var sourceAddress = Converter.AddressToString(SymbolService.Network.Facade.Network.PublicKeyToAddress(sourcePubKey.bytes).bytes);
        var targetAddress = Converter.AddressToString(SymbolService.Network.Facade.Network.PublicKeyToAddress(targetPubKey.bytes).bytes);
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
        string? magic;

        do
        {
            if (!lookupTable.TryGetValue(currentKeyHex, out var metadata))
            {
                Console.WriteLine($"Error: The chunk {currentKeyHex} lost.");
                return null;
            }

            lookupTable.Remove(currentKeyHex); // Prevent loop

            var chunk = ExtractChunk(metadata.metadataEntry);
            if (chunk == null)
            {
                return null;
            }

            var valueBytes = Converter.Utf8ToBytes(metadata.metadataEntry.value);
            txs.Add(SymbolService.CreateMetadataTx(
                sourcePubKey,
                targetPubKey,
                ulong.Parse(metadata.metadataEntry.scopedMetadataKey, NumberStyles.HexNumber),
                Converter.HexToBytes(Converter.BytesToHex(Converter.Xor(valueBytes, scrappedValueBytes))),
                (ushort)(scrappedValueBytes.Length - valueBytes.Length)
            ));

            magic = chunk.Value.magic;
            currentKeyHex = chunk.Value.nextKey.ToString("X26");
        } while (magic != "E");
        return txs;
    }

    public async Task<IEnumerable<IBaseTransaction>> CreateDestroyTxs(
        MetadataType type,
        PublicKey sourcePubKey,
        PublicKey targetPubKey,
        MosaicId targetId,
        byte[] payload,
        byte[]? additive = null,
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
            var packedChunk = MetalService.PackChunkBytes(magic, VERSION, additive, nextKey, chunkBytes);
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
        bool isBytes
    ) {
        var metadataPool = await SymbolService.SearchAccountMetadata(new AccountMetadataCriteria(source, target));
        return isBytes ? DecodeBytes(key, metadataPool) : Base64.Decode(Decode(key, metadataPool));
    }
    
    // Returns:
    //   - payload: Decoded metal contents
    //   - sourceAddress: Metadata source address
    //   - targetAddress: Metadata target address
    //   - key: Metadata key
    public async Task<(byte[] Payload, string SourceAddress, string TargetAddress, string Key)> FetchByMetalId(string metalId, bool bytes = true) {
        var metadataEntry = await GetFirstChunk(metalId);
        var payload = await Fetch(
            metadataEntry.sourceAddress,
            metadataEntry.targetAddress,
            metadataEntry.scopedMetadataKey,
            bytes
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