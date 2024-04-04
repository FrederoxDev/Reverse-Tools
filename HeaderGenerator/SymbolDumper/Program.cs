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

List<DumpedFuncInfo> dataToDump = [];

foreach (var symbol in reader.PublicSymbols)
{
    DumpedFuncInfo dumpedFuncInfo = new(symbol.Name, symbol.RelativeVirtualAddress);
    dataToDump.Add(dumpedFuncInfo);
}

var jsonWriteOptions = new JsonSerializerOptions
{
    WriteIndented = true,
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
    var jsonString = JsonSerializer.Serialize(dataToDump, jsonWriteOptions);
    File.WriteAllText(outputPath, jsonString);
    Console.WriteLine($"JSON data saved to {outputPath}");
}
catch (Exception ex)
{
    Console.WriteLine($"Failed to save JSON data: {ex.Message}");
    return -4;
}

return 0;

struct DumpedFuncInfo
{
    public string symbol { get; set; }
    public ulong address { get; set; }

    public DumpedFuncInfo(string symbol, ulong address)
    {
        this.symbol = symbol;
        this.address = address;
    }
};
