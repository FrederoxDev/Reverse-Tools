using SharpPdb.Native;
using SharpPdb.Windows;
using System.IO;
using System.Text.Json;
using System;

if (args.Length != 2)
{
    string exeName = Path.GetFileNameWithoutExtension(AppDomain.CurrentDomain.FriendlyName);
    Console.WriteLine($"Usage: {exeName} <pdb_path> <class_name>");
    return -1;
}

// Load the pdb
var reader = new PdbFileReader(args[0]);
List<DumpedFuncInfo> dataToDump = [];

foreach (var symbol in reader.PublicSymbols)
{
    if (!symbol.Name.Contains($"@{args[1]}@")) continue;

    DumpedFuncInfo dumpedFuncInfo = new(symbol.Name, symbol.RelativeVirtualAddress);
    dataToDump.Add(dumpedFuncInfo);
}

var jsonWriteOptions = new JsonSerializerOptions
{
    WriteIndented = true,
};

var jsonString = JsonSerializer.Serialize(dataToDump, jsonWriteOptions);
Console.Write(jsonString);

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
