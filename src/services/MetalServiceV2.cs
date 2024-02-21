using System.Diagnostics;
using System.Globalization;
using System.Text;
using SymbolSdk;
using SymbolSdk.Symbol;
using MetalForSymbol.utils;
using Org.BouncyCastle.Utilities.Encoders;

public class MetalServiceV2
{
    private SymbolService SymbolService;

    public MetalServiceV2(SymbolService _symbolService)
    {
        SymbolService = _symbolService;
    }
    
    public class ChunkData(Magic magic, byte version, ulong checksum, ulong nextKey, byte[] chunkPayload, bool text)
    {
        public Magic Magic = magic;
        public byte Version = version;
        public ulong Checksum = checksum;
        public ulong NextKey = nextKey;
        public byte[] ChunkPayload = chunkPayload;
        public readonly bool text = text;
    }

    private class ChunkDataV1 : ChunkData
    {
        public byte[] Addtive;
        public ChunkDataV1(Magic magic, byte version, ulong checksum, ulong nextKey, byte[] chunkPayload, byte[] additive, bool text) 
            : base(magic, version, checksum, nextKey, chunkPayload, text)
        {
            Magic = magic;
            Checksum = checksum;
            NextKey = nextKey;
            ChunkPayload = chunkPayload;
            Addtive = additive;
        }
    }
    
    private class ChunkDataV2 : ChunkData
    {
        public ushort Addtive;
        public ChunkDataV2(Magic magic, byte version, ulong checksum, ulong nextKey, byte[] chunkPayload, ushort additive, bool text) 
            : base(magic, version, checksum, nextKey, chunkPayload, text)
        {
            Magic = magic;
            Checksum = checksum;
            NextKey = nextKey;
            ChunkPayload = chunkPayload;
            Addtive = additive;
        }
    }
    
    public enum Magic {
        CHUNK = 0x00,
        END_CHUNK = 0x80,
    }

    private enum Flag
    {
        MAGIC = 0x80,
        TEXT = 0x40,
    }
    
    private const short DEFAULT_ADDITIVE = 0;
    private const short VERSION = 0x31;
    private const int HEADER_SIZE = 12;
    private const int CHUNK_PAYLOAD_MAX_SIZE = 1012;
    private const string METAL_ID_HEADER_HEX = "0B2A";
    
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
    public static ulong GenerateChecksum(byte[] input) {
        return MetalService.GenerateChecksum(input);
    }

    // Return 64 bytes hex string
    private static string RestoreMetadataHash(string metalId)
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
        byte[] chunkBytes,
        bool text = false
    )
    {
        // Append next scoped key into chunk's tail (except end of line)
        var value = new byte[chunkBytes.Length + HEADER_SIZE];
        Debug.Assert(value.Length <= 1024);

        // Header (12 bytes)
        var flags = (byte)magic & (byte)Flag.MAGIC | (text ? (byte)Flag.TEXT : 0);
        value[0] = (byte)flags;
        value[1] = (byte)((byte)version & 0xFF);
        Array.Copy(BitConverter.GetBytes(additive).Reverse().ToArray(), 0, value, 2, 2);
        Array.Copy(BitConverter.GetBytes(nextKey).Reverse().ToArray(), 0, value, 4, 8);
        
        // Payload (max 1012 bytes)
        Array.Copy(chunkBytes, 0, value, HEADER_SIZE, chunkBytes.Length);
        
        var key = GenerateMetadataKey(value);
        return (value, key);
    }

    public static (byte[] CombinedPayload, int TextChunks) CombinePayloadWithText(byte[] payload, string? text = null)
    {
        var textBytes = text != null ? Converter.Utf8ToBytes(text) : Array.Empty<byte>();
        var textSize = textBytes.Length % CHUNK_PAYLOAD_MAX_SIZE != 0 
            ? textBytes.Length + 1 // If textJson section end at mid-chunk then append null char
            : textBytes.Length;
        var combinedPayload = new byte[textSize + payload.Length];
        var offset = 0;
        
        if (textBytes.Length > 0) {
            Array.Copy(textBytes, 0, combinedPayload, offset, textBytes.Length);
            offset += textBytes.Length;
        }
        if (textBytes.Length % CHUNK_PAYLOAD_MAX_SIZE != 0) {
            // append null char as terminator
            combinedPayload[offset] = 0x00;
            offset++;
        }
        if (payload.Length > 0) {
            Array.Copy(payload, 0, combinedPayload, offset, payload.Length);
        }
        return (
            combinedPayload,
            (int)Math.Ceiling((double)textBytes.Length / CHUNK_PAYLOAD_MAX_SIZE)
        );
    }
    
    private static ulong CalculateMetadataKey(byte[] payload, short additive = DEFAULT_ADDITIVE, string? text = null)
    {
        var (combinedPayload, textChunks) = CombinePayloadWithText(payload, text);
        var chunks = (int)Math.Ceiling((double)combinedPayload.Length / CHUNK_PAYLOAD_MAX_SIZE);
        var nextKey = GenerateChecksum(combinedPayload);
        for (var i = chunks - 1; i >= 0; i--)
        {
            var magic = i == chunks - 1 ? Magic.END_CHUNK : Magic.CHUNK;
            var chunkBytes = combinedPayload.Skip(i * CHUNK_PAYLOAD_MAX_SIZE).Take(CHUNK_PAYLOAD_MAX_SIZE).ToArray();
            var result = PackChunkBytes(magic, VERSION, additive, nextKey, chunkBytes);
            nextKey = result.Key;
        }
        return nextKey;
    }
    
    // Verify metadata key with calculated one. "additive" must be specified when using non-default one.
    public static bool VerifyMetadataKey (
        ulong key,
        byte[] payload, 
        short additive = DEFAULT_ADDITIVE,
        string? text = null
    ) {
        return CalculateMetadataKey(payload, additive, text).Equals(key);   
    }
    
    private static ChunkData? ExtractChunk(MetadataEntry chunk)
    {
        var chunkValue = Converter.HexToBytes(chunk.value);
        var magic = (byte)(chunkValue[0] & (byte)Flag.MAGIC) == (byte)Magic.END_CHUNK ? Magic.END_CHUNK : Magic.CHUNK;
        var version = chunkValue[1];
        if (version != VERSION)
        {
            var result = MetalService.ExtractChunk(chunk);
            if(result == null) throw new Exception("Error: V1 chunk is something brokern.");
            var _magic = result.Value.magic == "E" ? Magic.END_CHUNK : Magic.CHUNK;
            var _additive = result.Value.additive;
            var _checkSum = ulong.Parse(result.Value.checksum, NumberStyles.HexNumber);
            var _chunkPayload = Base64.Decode(result.Value.chunkPayload);
            return new ChunkDataV1(_magic, version, _checkSum, result.Value.nextKey, _chunkPayload, _additive, false);
        }
        
        var checksum = GenerateMetadataKey(chunkValue);
        if (!checksum.Equals(ulong.Parse(chunk.scopedMetadataKey, NumberStyles.HexNumber)))
        {
            Console.WriteLine($"Error: The chunk {chunk.scopedMetadataKey} is broken (calculated={checksum})");
            return null;
        }
        var text = (chunkValue[0] & (byte)Flag.TEXT) != 0;
        var addr = chunkValue.ToList().GetRange(2, 2).ToArray();
        var additive = BitConverter.ToUInt16(addr.Reverse().ToArray(), 0);
        var keyr = chunkValue.ToList().GetRange(4, 8).ToArray();
        var nextKey = BitConverter.ToUInt64(keyr.Reverse().ToArray());
        var chunkPayload = chunkValue.ToList().GetRange(HEADER_SIZE, chunkValue.Length - HEADER_SIZE).ToArray();
        return new ChunkDataV2(magic, version, checksum, nextKey, chunkPayload, additive, text);
    }

    private static (byte[] ChunkPayload, byte[]? ChunkText) SplitChunkPayloadAndText(ChunkData chunkData)
    {
        if (!chunkData.text)
        {
            // No text in the chunk
            return (chunkData.ChunkPayload, null);
        }
        
        // Extract text section until null char is encountered.
        var textBytes = new List<byte>();
        for (var i = 0; i < chunkData.ChunkPayload.Length && chunkData.ChunkPayload[i] != 0; i++) {
            textBytes.Add(chunkData.ChunkPayload[i]);
        }

        var chunkPayload = new byte[chunkData.ChunkPayload.Length - textBytes.Count - 1];
        Array.Copy(chunkData.ChunkPayload, textBytes.Count + 1, chunkPayload, 0, chunkPayload.Length);

        return (chunkPayload, textBytes.ToArray());
    }
    
    private static (byte[] DecodedPayload, byte[]? DecodedText) Decode(string currentKeyHex, IEnumerable<Metadata> metadataPool)
    {
        var lookupTable = CreateMetadataLookupTable(metadataPool);
        var decodedPayload = new List<byte>{};
        var decodedText = new List<byte>{};
        byte? version = null;
        Magic magic;
        do
        {
            if (!lookupTable.Remove(currentKeyHex, out var metadata)) {
                Console.Error.WriteLine($"Error: The chunk {currentKeyHex} lost");
                break;
            }

            // Prevent loop
            var result = ExtractChunk(metadata.metadataEntry);
            if (result == null) {
                break;
            }

            if (version != null && version != result.Version)
            {
                Console.Error.WriteLine("Error: Inconsistent chunk versions.");
                break;
            }

            version = result.Version;
            magic = result.Magic;
            currentKeyHex = result.NextKey.ToString("X16");

            var (chunkPayload, chunkText) = SplitChunkPayloadAndText(result);

            if (chunkPayload.Length != 0)
            {
                var payloadBuffer = new byte[decodedPayload.Count + chunkPayload.Length];
                decodedPayload.CopyTo(payloadBuffer);
                chunkPayload.CopyTo(payloadBuffer, decodedPayload.Count);
                decodedPayload = payloadBuffer.ToList();
            }
            
            if (chunkText != null && chunkText.Length != 0)
            {
                var textBuffer = new byte[decodedText.Count + chunkText.Length];
                decodedText.CopyTo(textBuffer);
                chunkText.CopyTo(textBuffer, decodedText.Count);
                decodedText = textBuffer.ToList();
            }
        } while (magic != Magic.END_CHUNK);
        var _decodedPayload = version == VERSION
            ? decodedPayload.ToArray()
            : Base64.Decode(Converter.BytesToHex(decodedPayload.ToArray()));
        var _decodedText = decodedText.Count != 0 ? decodedText.ToArray() : null;
        return (_decodedPayload, _decodedText);
    }
    
    // Returns:
    // - key: Metadata key of first chunk (undefined when no transactions were created)
    // - txs: List of metadata transaction (InnerTransaction for aggregate tx)
    // - additive: Actual additive that been used during encoding. You should store this for verifying the metal.
    public async Task<(ulong Key, List<IBaseTransaction> Txs, short? Additive)> CreateForgeTxs(
        MetadataType type,
        PublicKey sourcePubKey,
        PublicKey targetPubKey,
        byte[] payload,
        string? targetId = null,
        short? additive = null,
        string? text = null,
        Metadata[]? metadataPool = null)
    {
        if(type is MetadataType.Mosaic or MetadataType.Namespace && targetId == null) throw new ArgumentNullException(nameof(targetId), "targetId is required for mosaic or namespace metadata");
        additive ??= DEFAULT_ADDITIVE;
        var lookupTable = CreateMetadataLookupTable(metadataPool);
        var txs = new List<IBaseTransaction>();
        var keys = new List<string>();
        var ( combinedPayload, textChunks ) = CombinePayloadWithText(payload, text);
        var chunks = (int) Math.Ceiling((double) combinedPayload.Length / CHUNK_PAYLOAD_MAX_SIZE);
        var nextKey = GenerateChecksum(combinedPayload);

        for (var i = chunks - 1; i >= 0; i--)
        {
            var magic = i == chunks - 1 ? Magic.END_CHUNK : Magic.CHUNK;
            var chunkBytes = combinedPayload.Skip(i * CHUNK_PAYLOAD_MAX_SIZE).Take(CHUNK_PAYLOAD_MAX_SIZE).ToArray();

            var (value, key) = PackChunkBytes(magic, VERSION, (short) additive, nextKey, chunkBytes, i < textChunks);

            if (keys.Contains(key.ToString("X16")))
            {
                Console.WriteLine($"Warning: Scoped key \"{key.ToString("X16")}\" has been conflicted. Trying another additive.");
                // Retry with another additive via recursive call
                return await CreateForgeTxs(
                    type,
                    sourcePubKey,
                    targetPubKey,
                    payload,
                    targetId,
                    GenerateRandomAdditive(),
                    text,
                    metadataPool);
            }

            // Only non on-chain data to be announced.
            if (!lookupTable.ContainsKey(key.ToString("X16")))
            {
                txs.Add(SymbolService.CreateMetadataTx(
                    type,
                    sourcePubKey,
                    targetPubKey,
                    key,
                    value,
                    (ushort)value.Length,
                    targetId != null ? ulong.Parse(targetId, NumberStyles.HexNumber) : null));
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
                type,
                sourcePubKey,
                targetPubKey,
                ulong.Parse(metadata.metadataEntry.scopedMetadataKey, NumberStyles.HexNumber),
                Converter.Xor(valueBytes, scrappedValueBytes),
                (ushort)(scrappedValueBytes.Length - valueBytes.Length)
            ));

            magic = chunk.Magic;
            currentKeyHex = chunk.NextKey.ToString("X16");
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
        string? text = null,
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
        var scrappedValueBytes = Array.Empty<byte>();
        var ( combinedPayload, textChunks ) = CombinePayloadWithText(payload, text);
        var payloadBase64Bytes = Encoding.UTF8.GetBytes(Convert.ToBase64String(payload));
        var chunks = (int) Math.Ceiling(combinedPayload.Length / (double) CHUNK_PAYLOAD_MAX_SIZE);
        var txs = new List<IBaseTransaction>();
        var nextKey = GenerateChecksum(combinedPayload);
        
        for (var i = chunks - 1; i >= 0; i--)
        {
            var magic = i == chunks - 1 ? Magic.END_CHUNK : Magic.CHUNK;
            var chunkBytes = payloadBase64Bytes.Skip(i * CHUNK_PAYLOAD_MAX_SIZE).Take(CHUNK_PAYLOAD_MAX_SIZE).ToArray();
            var packedChunk = PackChunkBytes(magic, VERSION, (short)additive, nextKey, chunkBytes, i < textChunks);
            var key = packedChunk.Key;

            lookupTable.TryGetValue(key.ToString("X16"), out var onChainMetadata);
            if (onChainMetadata != null)
            {
                // Only on-chain data to be announced.
                var valueBytes = Converter.HexToBytes(onChainMetadata.metadataEntry.value);
                var xorValue = Converter.Xor(valueBytes, scrappedValueBytes);
                var metadataTx = SymbolService.CreateMetadataTx(
                    type,
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
        
        foreach (var tx in txs)
        {
            switch (tx.Type.Value)
            {
                case 16708:
                    var accountMetadataTx = tx as AccountMetadataTransactionV1;
                    var accountMetadataKeyHex = accountMetadataTx?.ScopedMetadataKey.ToString("X16");
                    if (accountMetadataKeyHex != null && lookupTable.ContainsKey(accountMetadataKeyHex))
                    {
                        Console.WriteLine($"{accountMetadataKeyHex}: Already exists on the chain.");
                        if (accountMetadataTx != null) collisions.Add(accountMetadataTx.ScopedMetadataKey);
                    }
                    break;
                case 16964:
                    var mosaicMetadataTx = tx as MosaicMetadataTransactionV1;
                    var mosaicKeyHex = mosaicMetadataTx?.ScopedMetadataKey.ToString("X16");
                    if (mosaicKeyHex != null && lookupTable.ContainsKey(mosaicKeyHex))
                    {
                        Console.WriteLine($"{mosaicKeyHex}: Already exists on the chain.");
                        if (mosaicMetadataTx != null) collisions.Add(mosaicMetadataTx.ScopedMetadataKey);
                    }
                    break;
                case 17220:
                    var namespaceMetadataTx = tx as MosaicMetadataTransactionV1;
                    var namespaceKeyHex = namespaceMetadataTx?.ScopedMetadataKey.ToString("X16");
                    if (namespaceKeyHex != null && lookupTable.ContainsKey(namespaceKeyHex))
                    {
                        Console.WriteLine($"{namespaceKeyHex}: Already exists on the chain.");
                        if (namespaceMetadataTx != null) collisions.Add(namespaceMetadataTx.ScopedMetadataKey);
                    }
                    break;
                default:
                    continue;
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
        var (decodedPayload, _) = Decode(
            key,
            metadataPool ??
            await SymbolService.SearchAccountMetadata(new AccountMetadataCriteria(sourceAddress, targetAddress)
            {
                SourceAddress = sourceAddress,
                TargetAddress = targetAddress
            }));

        var mismatches = 0;
        var maxLength = Math.Max(payload.Length, decodedPayload.Length);

        for (var i = 0; i < maxLength; i++)
        {
            if (payload[i] != decodedPayload[i])
            {
                mismatches++;
            }
        }

        return (maxLength, mismatches);
    }
    
    public async Task<MetadataEntry> GetFirstChunk(string metalId) {
        return await SymbolService.GetMetadataByHash(RestoreMetadataHash(metalId));
    }

    public async Task<(byte[] DecodedPayload, byte[]? DecodedText)> Fetch(
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
    public async Task<(byte[] Payload, byte[]? text, string SourceAddress, string TargetAddress, string Key)> FetchByMetalId(string metalId, bool isKey = false) {
        var metadataEntry = await GetFirstChunk(metalId);
        var (payload, text)= await Fetch(
            metadataEntry.sourceAddress,
            metadataEntry.targetAddress,
            metadataEntry.scopedMetadataKey,
            isKey
        );
        return (payload, text, metadataEntry.sourceAddress, metadataEntry.targetAddress, metadataEntry.scopedMetadataKey);
    }
}