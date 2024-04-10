using Newtonsoft.Json.Linq;
using System.Diagnostics;

internal class Program {
    public static Dictionary<ulong, List<string>> gAddressToSymbols = [];
    public static Dictionary<string, WindowsVtable> gWindowsVtables = [];

    static void Main(string[] args)
    {
        Stopwatch stopwatch = new Stopwatch();
        stopwatch.Start();

        LoadWindowsVtables();
        LoadWindowsSymbols();

        stopwatch.Stop();
        Console.WriteLine($"Loading dumped data took: {stopwatch.Elapsed.TotalSeconds}");

        stopwatch.Restart();

        HeaderGenerator headerGenerator = new HeaderGenerator(
            gWindowsVtables,
            gAddressToSymbols
        );

        headerGenerator.Generate();
        stopwatch.Stop();
        Console.WriteLine($"First pass: {stopwatch.Elapsed.TotalSeconds}s total, {stopwatch.Elapsed.TotalMilliseconds / 277.0f}ms each");

        Console.ReadLine();
    }

    static void LoadWindowsVtables()
    {
        string windowsVtable = File.ReadAllText("C:/Users/blake/AppData/Roaming/Amethyst/tools/windows_vtable.json");
        JObject jsonObject = JObject.Parse(windowsVtable);

        foreach (var entry in jsonObject)
        {
            string className = entry.Key;

            var address = entry.Value!["vtable_ea"]!.Value<ulong>()!;
            var entries = entry.Value!["entries"]!.ToObject<List<ulong>>()!;
            var symbol_set = entry.Value!["virtual_symbol_set"]!.ToObject<HashSet<string>>()!;

            gWindowsVtables[className] = new(className, address, entries, symbol_set);
        }
    }

    static void LoadWindowsSymbols()
    {
        string json = File.ReadAllText("C:/Users/blake/AppData/Roaming/Amethyst/tools/server_symbols.json");
        JObject jsonObject = JObject.Parse(json);
        JObject addressToSymbols = jsonObject["address_to_symbols"]!.ToObject<JObject>()!;

        foreach (var entry in addressToSymbols)
        {
            ulong symbolAddress = ulong.Parse(entry.Key);
            List<string> symbols = entry.Value!.ToObject<List<string>>()!;
            gAddressToSymbols.Add(symbolAddress, symbols);
        }
    }
}
