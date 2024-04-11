using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

internal class VtableEntry
{
    public bool mSolved;
    public HashSet<string> mOptions;

    public VtableEntry()
    {
        mSolved = false;
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
        return mOptions.First();
    }
}

