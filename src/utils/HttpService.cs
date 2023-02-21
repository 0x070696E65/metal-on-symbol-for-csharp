namespace MetalForSymbol.utils;

public class HttpService
{
    public static async Task<string> GetJsonAsync(string url)
    {
        using var httpClient = new HttpClient();
        using var response = await httpClient.GetAsync(url);
        
        response.EnsureSuccessStatusCode(); // ステータスコードが200-299であることを確認

        var responseContent = await response.Content.ReadAsStringAsync();
        return responseContent;
    }
}