using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

internal class Target
{
    public string mClassName;
    public HashSet<string> mRemainingSymbols;
    public List<VtableEntry> mVtable;
    public bool mVtableSetsDirty;

    public Target(WindowsVtable windowsVtable)
    {
        mClassName = windowsVtable.mName;
        mRemainingSymbols = windowsVtable.mVirtualSymbolSet;
        mVtable = [];
        
        for (int i = 0; i < windowsVtable.mEntries.Count; i++)
        {
            mVtable.Add(new());
        }

        for (int i = 0; i < windowsVtable.mEntries.Count; i++) 
        {
            HashSet<string> options = new(Program.gAddressToSymbols[windowsVtable.mEntries[i]]);
            options.IntersectWith(mRemainingSymbols);
            mVtable[i].mOptions = options;
        }
    }

    public void SolveEntry(int vtableIndex, string symbol)
    {
        // Remove it from the set of possible options and mark vtable as dirty
        mRemainingSymbols.Remove(symbol);
        mVtableSetsDirty = true;
        mVtable[vtableIndex].Solve(symbol);
    }

    public void SolveRemaining()
    {
        // Nothing has changed since the last time
        if (!mVtableSetsDirty) return;

        while (true)
        {
            bool didSolveAnything = false;

            // Solves any vtable entries with 1 option
            foreach (VtableEntry entry in mVtable)
            {
                if (entry.mSolved) continue;

                // Take the intersection of the two sets and check if 1 symbol remains.
                entry.mOptions.IntersectWith(mRemainingSymbols);
                didSolveAnything = entry.TrySolve();
            }

            if (!didSolveAnything) break;
        }

        // Mark as clean as there are no unresolved entries.
        mVtableSetsDirty = false;
    }
}
