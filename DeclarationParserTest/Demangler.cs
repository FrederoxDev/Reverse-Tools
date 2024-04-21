using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AmethystHeaders
{
    internal class Demangler
    {
        private Process process;

        public Demangler()
        {
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = "demumble.exe",
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            process = new Process();
            process.StartInfo = startInfo;
            process.Start();
        }

        ~Demangler()
        {
            if (!process.HasExited)
            {
                process.StandardInput.Close();
                process.WaitForExit();
                process.Close();
            }
        }

        public string? Demangle(string symbol)
        {
            using (StreamWriter sw = process.StandardInput)
            {
                sw.WriteLine(symbol);
            }

            return process.StandardOutput.ReadLine();
        }
    }
}
