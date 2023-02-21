namespace MetalForSymbol.models;

public enum MetadataType {
 Account = 0,
 Mosaic = 1,
 Namespace = 2
}

public class Metadata
{
    public string id { get; set; } = null!;
    public MetadataEntry metadataEntry { get; set; } = null!;
}

public class MetadataEntry { 
    public int version { get; set; }
    public string compositeHash { get; set; } = null!;
    public string sourceAddress { get; set; } = null!;
    public string targetAddress { get; set; } = null!;
    public string scopedMetadataKey { get; set; } = null!;
    public string targetId { get; set; } = null!;
    public int metadataType { get; set; }
    public int valueSize { get; set; }
    public string value { get; set; } = null!;
}

public class Pagination
{
    public int pageNumber { get; set; }
    public int pageSize { get; set; }
}

public class Root
{
    public List<Metadata> data { get; set; } = null!;
    public Pagination pagination { get; set; } = null!;
}