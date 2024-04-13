using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

internal class VtableEntry
{
    public bool mIsInherited;
    public bool mSolved;
    public ulong mAddress;
    public HashSet<string> mOptions;

    public VtableEntry(ulong address)
    {
        mAddress = address;
        mSolved = false;
        mIsInherited = false;
        mOptions = new();
    }

    public void Solve(string symbol)
    {
        mSolved = true;
        mOptions.Clear();
        mOptions.Add(symbol);
    }

    public bool TrySolve()
    {
        if (mOptions.Count == 1)
        {
            mSolved = true;
            return true;
        }

        return false;
    }

    public string GetSolved()
    {
        if (mIsInherited)
        {
            return "Inherited";
        }

        return mOptions.First();
    }
}

