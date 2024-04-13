using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

internal class HeaderGenerator
{
    public HeaderGenerator() {}

    public void Generate(List<string> targets)
    {
        foreach (var target in targets)
        {
            AddTarget(target);
            var dependants = Program.gDependencies[target];
            
            foreach (var dependant in dependants)
            {
                AddTarget(dependant);

                Target? dependantTarget;
                if (!Program.gTargets.TryGetValue(dependant, out dependantTarget)) continue;

                dependantTarget.AddParent(Program.gTargets[target]);
            }
        }

        int count = 0;

        while (true)
        {
            count += 1;
            bool didPropagate = false;
            Console.WriteLine($"Propagation pass: {count}");

            foreach (var target in Program.gTargets)
            {
                didPropagate |= PropagateTarget(target.Key);
                didPropagate |= target.Value.SolveRemaining();
            }

            if (!didPropagate) break;
        }

        foreach (var target in targets)
        {
            Program.gFinalData.Add(target, Program.gTargets[target]);
        }

        Program.gTargets.Clear();
    }

    public void AddTarget(string className)
    {
        // Target has already been created.
        if (Program.gTargets.ContainsKey(className)) return;
        
        WindowsVtable? winVtable;
        if (!Program.gWindowsVtables.TryGetValue(className, out winVtable)) return;

        Target target = new(winVtable);
        Program.gTargets.Add(className, target);
        Program.targetsEvaluated += 1;
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
