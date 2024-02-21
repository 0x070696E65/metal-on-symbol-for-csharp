using Newtonsoft.Json;

namespace MetalOnSymbol.services;

public class MetalSeal(long length, string? mimeType = null, string? name = null, string? comment = null)
{
    private const string SCHEMA = "seal1";
    private static readonly string[] COMPAT = [SCHEMA];
    
    public readonly long Length = length;
    public const string Schema = SCHEMA;
    public readonly string? MimeType = mimeType;
    public readonly string? Name = name;
    public readonly string? Comment = comment;
    
    static bool IsMetalSealHead(IReadOnlyList<object?>? value)
    {
        return
            value?[0] is string &&
            COMPAT.Contains((string)value[0]!) &&
            (string) value[0]! == SCHEMA &&
            value[1] is long &&
            value[2] is string or null &&
            value[3] is string or null &&
            value[4] is string or null;
    }

    public string Stringify()
    {
        var array = new object?[] {Schema, Length, MimeType, Name, Comment};
        return JsonConvert.SerializeObject(array);
    }

    static public MetalSeal Parse(string json)
    {
        var array = JsonConvert.DeserializeObject<object[]>(json);
        if (array == null || array.GetType() != typeof(object[])|| IsMetalSealHead(array) == false)
        {
            throw new Exception("Malformed seal JSON.");
        }

        return new MetalSeal(
            (long)array[1],
            (string)array[2],
            (string)array[3],
            (string)array[4]
        );
    }
}