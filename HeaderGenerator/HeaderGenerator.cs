using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

internal class HeaderGenerator
{
    public HeaderGenerator() {}

    public void Generate()
    {
        List<string> targets = new List<string>();
        targets.Add("Actor");
        targets.Add("Mob");

        foreach (var target in targets)
        {
            AddTarget(target);
            var dependants = Program.gDependencies[target];
            
            foreach (var dependant in dependants)
            {
                AddTarget(dependant);
            }
        }


        while (true)
        {
            bool didPropagate = false;

            foreach (var target in Program.gTargets)
            {
                didPropagate |= PropagateTarget(target.Key);
                didPropagate |= target.Value.SolveRemaining();
            }

            if (!didPropagate) break;
        }

        Program.gTargets["Actor"].LogSolved();
        Program.gTargets["Mob"].LogSolved();
    }

    public void AddTarget(string className)
    {
        // Target has already been created.
        if (Program.gTargets.ContainsKey(className)) return;
        
        WindowsVtable? winVtable;
        if (!Program.gWindowsVtables.TryGetValue(className, out winVtable)) return;

        Target target = new(winVtable);
        target.SolveRemaining();
        Program.gTargets.Add(className, target);
    }

    public bool PropagateTarget(string className)
    {
        bool didPropagate = false;
        Target self = Program.gTargets[className];

        foreach (var dependant in Program.gDependencies[className])
        {
            Target? dependency;
            if (!Program.gTargets.TryGetValue(dependant, out dependency)) continue;
            didPropagate |= Target.PropagateSymbols(self, dependency);
        }

        return didPropagate;
    }
}
