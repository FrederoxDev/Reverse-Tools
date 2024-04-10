using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

internal class WindowsVtable
{
    public string mName;
    public ulong mAddress;
    public List<ulong> mEntries;

    // Set of all possible virtual symbols
    public HashSet<string> mVirtualSymbolSet;

    public WindowsVtable(string name, ulong address, List<ulong> entries, HashSet<string> virtualSymbolSet)
    {
        mName = name;
        mAddress = address;
        mEntries = entries;
        mVirtualSymbolSet = virtualSymbolSet;
    }
}