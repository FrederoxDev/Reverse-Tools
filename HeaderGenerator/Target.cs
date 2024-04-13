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
    public List<Target> mParents;

    public Target(WindowsVtable windowsVtable)
    {
        mClassName = windowsVtable.mName;
        mRemainingSymbols = windowsVtable.mVirtualSymbolSet;
        mVtable = [];
        mParents = new();
        
        for (int i = 0; i < windowsVtable.mEntries.Count; i++)
        {
            mVtable.Add(new(windowsVtable.mEntries[i]));
        }

        for (int i = 0; i < windowsVtable.mEntries.Count; i++) 
        {
            HashSet<string> options = new(Program.gAddressToSymbols[windowsVtable.mEntries[i]]);
            options.IntersectWith(mRemainingSymbols);
            mVtable[i].mOptions = options;
        }

        mVtableSetsDirty = true;
    }

    public void AddParent(Target parent)
    {
        // Mark any functions which are inherited as such so the resolver
        // doesn't try and resolve them.
        for (int i = 0; i < parent.mVtable.Count; i++)
        {
            if (mVtable[i].mAddress == parent.mVtable[i].mAddress)
            {
                mVtable[i].mSolved = true;
                mVtable[i].mIsInherited = true;
            }
        }
    }

    public bool TrySolveEntry(int vtableIndex, string symbol)
    {
        HashSet<string> options = new(mVtable[vtableIndex].mOptions);
        options.IntersectWith(mRemainingSymbols);

        if (options.Contains(symbol))
        {
            SolveEntry(vtableIndex, symbol);
            return true;
        }

        return false;
    }

    public void SolveEntry(int vtableIndex, string symbol)
    {
        // Remove it from the set of possible options and mark vtable as dirty
        mRemainingSymbols.Remove(symbol);
        mVtableSetsDirty = true;
        mVtable[vtableIndex].Solve(symbol);
    }

    public bool SolveRemaining()
    {
        // Nothing has changed since the last time
        if (!mVtableSetsDirty) return false;
        bool didEverSolveAnything = false;

        while (true)
        {
            bool didSolveAnything = false;

            // Solves any vtable entries with 1 option
            foreach (VtableEntry entry in mVtable)
            {
                if (entry.mSolved) continue;
                entry.mOptions.IntersectWith(mRemainingSymbols);
                didSolveAnything |= entry.TrySolve();
            }

            didEverSolveAnything |= didSolveAnything;
            if (!didSolveAnything) break;
        }

        // Mark as clean as there are no unresolved entries.
        mVtableSetsDirty = false;
        return didEverSolveAnything;
    }

    public void LogSolved()
    {
        Console.WriteLine($"vtable for {mClassName}:");
        int total = 0;
        int success = 0;

        foreach (VtableEntry entry in mVtable)
        {
            total += 1;

            if (!entry.mSolved)
            {
                Console.WriteLine($"--- {entry.mOptions.Count} remaining options. ---");
                foreach (var opt in entry.mOptions)
                {
                    Console.WriteLine(opt);
                }

                Console.WriteLine("--- end ---\n");
            }
            else
            {
                success += 1;

                if (entry.mIsInherited)
                {
                    Console.WriteLine("Inherited");
                }
                else
                {
                    Console.WriteLine(entry.mOptions.First());
                }
            }
        }

        Console.WriteLine($"Solved {success} / {total}\n");
    }

    static string ChangeSymbolClass(string className, string newClass, string symbol)
    {
        return ReplaceFirst(symbol, $"@{className}@@", $"@{newClass}@@");
    }

    public static bool PropagateSymbols(Target parent, Target child)
    {
        bool didSolveAnything = false;

        for (int i = 0; i < parent.mVtable.Count; i++)
        {
            var parentVtable = parent.mVtable[i];
            var childVtable = child.mVtable[i];

            // Both are already solved, or neither are solved!
            if (parentVtable.mSolved == childVtable.mSolved) continue;

            // Propagate name downwards
            if (childVtable.mSolved && !childVtable.mIsInherited)
            {
                string parentSolution = ChangeSymbolClass(child.mClassName, parent.mClassName, childVtable.GetSolved());
                didSolveAnything |= parent.TrySolveEntry(i, parentSolution);
            }

            if (parentVtable.mSolved)
            {
                string childSolution = ChangeSymbolClass(parent.mClassName, child.mClassName, parentVtable.GetSolved());

                if (child.TrySolveEntry(i, childSolution))
                {
                    didSolveAnything = true;
                    continue;
                }

                child.SolveEntry(i, parentVtable.GetSolved());
            }
        }

        return didSolveAnything;
    }

    static string ReplaceFirst(string text, string search, string replace)
    {
        int pos = text.IndexOf(search);
        if (pos < 0)
        {
            return text;
        }
        return text.Substring(0, pos) + replace + text.Substring(pos + search.Length);
    }
}

