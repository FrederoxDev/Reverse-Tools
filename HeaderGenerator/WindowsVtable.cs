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
    public HashSet<string> mVirtualSymbolSet;
    public List<string> mDependantClasses;

    public WindowsVtable(string name, ulong address, List<ulong> entries, HashSet<string> virtualSymbolSet, List<string> dependantClasses)
    {
        mName = name;
        mAddress = address;
        mEntries = entries;
        mVirtualSymbolSet = virtualSymbolSet;
        mDependantClasses = dependantClasses;
    }
}