using SharpPdb.Native;
using SharpPdb.Windows;
using System.IO;
using System.Text.Json;
using System;

if (args.Length != 1)
{
    string exeName = Path.GetFileNameWithoutExtension(AppDomain.CurrentDomain.FriendlyName);
    Console.WriteLine($"Usage: {exeName} <pdb_path>");
    return -1;
}

// Load the pdb
PdbFileReader? reader = null;
try {
    reader = new PdbFileReader(args[0]);
}
catch {
    Console.WriteLine("Failed to read pdb, ensure the path is correct.");
    return -2;
}

OutputData data = new OutputData();

foreach (var symbol in reader.PublicSymbols)
{
    ulong basedAddress = 0x140000000 + symbol.RelativeVirtualAddress;

    if(!data.address_to_symbols.ContainsKey(basedAddress))
    {
        data.address_to_symbols.Add(basedAddress, new List<string>());
    }

    data.address_to_symbols[basedAddress].Add(symbol.Name);

    string demangled = symbol.GetUndecoratedName();
    if (demangled.Contains("`vftable'"))
    {
        SymbolInfo symbolInfo = new(symbol.Name, demangled, basedAddress);
        data.vtables.Add(symbolInfo);
    }
}

var jsonWriteOptions = new JsonSerializerOptions
{
    WriteIndented = true,
    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
};

string amethystPath = Environment.GetEnvironmentVariable("Amethyst");
if (string.IsNullOrEmpty(amethystPath))
{
    Console.WriteLine("%Amethyst% environment variable is not set.");
    return -3;
}

string outputPath = Path.Combine(amethystPath, "tools", "server_symbols.json");

try
{
    var jsonString = JsonSerializer.Serialize(data, jsonWriteOptions);
    File.WriteAllText(outputPath, jsonString);
    Console.WriteLine($"JSON data saved to {outputPath}");
}
catch (Exception ex)
{
    Console.WriteLine($"Failed to save JSON data: {ex.Message}");
    return -4;
}

return 0;

struct OutputData
{
    public Dictionary<ulong, List<string>> address_to_symbols { get; set; } = [];
    public List<SymbolInfo> vtables { get; set; } = [];

    public OutputData() {}
}

struct SymbolInfo
{
    public string symbol { get; set; }
    public string demangled {  get; set; }
    public ulong address { get; set; }

    public SymbolInfo(string symbol, string demangled_name, ulong address)
    {
        this.symbol = symbol;
        this.demangled = demangled_name;
        this.address = address;
    }

    
};