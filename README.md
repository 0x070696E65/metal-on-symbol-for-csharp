# Metal on Symbol for Csharp

## Metal ってなに?
Metal（メタル）とは Symbol ブロックチェーンに、任意の（サイズの）データを書き込んだり読み込んだりするためのプロトコルです。 簡単に言えば、Symbol ブロックチェーンをオンラインの不揮発性メモリ（ROM）として使用できます。
<br>
<a href="https://github.com/OPENSPHERE-Inc/metal-on-symbol" target="_blank">詳しくはこちら</a>
<br><br>
自分のために作ったのでドキュメントはいずれちゃんと書きます。もし使いたい方がいればテストネットで試してから使ってください。
以下（Metal on Symbol）を読んでもらって理解したのちに活用してください。<br>
<a href="https://github.com/OPENSPHERE-Inc/metal-on-symbol" target="_blank">詳しくはこちら</a>

## Install
<a href="https://www.nuget.org/packages/MetalOnSymbol" target="_blank">Metal on Symbol for C#</a><br>
Nugetからインストールしてください<br>

## Usage
### Forge
```c#
using SymbolSdk;
using SymbolSdk.Symbol;
using MetalForSymbol.models;
using MetalForSymbol.services;

const string filePath = "FILE_PATH";
var fileData = File.ReadAllBytes(filePath);

var config = new SymbolServiceConfig("NODE_URL");
var symbolService = new SymbolService(config);
await symbolService.Init();

var metalService = new MetalServiceV2(symbolService);

var alicePrivateKey = new PrivateKey("SOURCE_PRIVATE_KEY");
var aliceKeyPair = new KeyPair(alicePrivateKey);

var bobPrivateKey = new PrivateKey("TARGET_PRIVATE_KEY");
var bobKeyPair = new KeyPair(bobPrivateKey);

// トランザクション構築
var (key, txs, _) = await metalService.CreateForgeTxs(aliceKeyPair.PublicKey, bobKeyPair.PublicKey, fileData);

// MetalIDの確認
var metalId = metalService.CalculateMetalId(
        MetadataType.Account, 
        aliceKeyPair.PublicKey,
        bobKeyPair.PublicKey,
        key 
        );
Console.WriteLine($"MetalID: {metalId}");

// 署名
var batches = symbolService.BuildSignedAggregateCompleteTxBatches(
        txs,
        aliceKeyPair,
        new List<KeyPair>(){bobKeyPair}
);

// 手数料確認
var totalFee = batches.Select(batch => (long)batch.Fee.Value).Sum();
Console.WriteLine($"Total Fee: {totalFee}");

// アナウンス
var result = await symbolService.ExecuteBatches(batches);
Console.WriteLine(result);
```

### Fetch
```c#
var metalId = "METAL_ID";
var result = await metalService.FetchByMetalId(metalId);

//バイト配列をバイナリファイルに出力する
var path = "SAVE_PATH";
await using (var fs = new FileStream(path, System.IO.FileMode.Create))
{
        fs.Write(result.Payload, 0, result.Payload.Length);
}
Console.WriteLine("Complete");
```
