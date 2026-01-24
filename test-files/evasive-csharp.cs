using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace EvasivePatterns
{
    /// <summary>
    /// Test file for C# LINQ taint tunnel detection
    /// These patterns should be detected as command injection via LINQ
    /// </summary>
    public class LinqTaintTunnel
    {
        // Pattern 1: LINQ Select transforms tainted data for shell execution
        public void ExecuteFromUserInputList(string userInput)
        {
            var commands = new List<string> { userInput };  // Tainted collection

            // DETECT: LINQ Select transforms tainted data for shell
            var shellCommands = commands.Select(x => $"/c {x}").ToList();

            Process.Start("cmd.exe", shellCommands.FirstOrDefault());
        }

        // Pattern 2: Collection built with tainted .Add(), then LINQ to sink
        public void CollectionWithAdd(string input)
        {
            var items = new List<string>();
            items.Add(input);  // Tainted data added

            // DETECT: LINQ Select builds shell commands
            var processed = items.Select(cmd => "/c " + cmd).First();

            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = processed
            };
            Process.Start(psi);
        }

        // Pattern 3: LINQ chain with FirstOrDefault flowing to Process.Start
        public void LinqChainToProcess(List<string> userInputs)
        {
            // DETECT: LINQ result flows to Process.Start
            var result = userInputs
                .Where(x => x.Length > 0)
                .Select(x => $"-Command {x}")
                .FirstOrDefault();

            Process.Start("powershell.exe", result);
        }

        // Pattern 4: LINQ Aggregate tunnels taint
        public void AggregatePattern(string[] args)
        {
            // DETECT: LINQ aggregation tunnels tainted data to sink
            var combined = args.Aggregate((a, b) => a + " && " + b);

            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c {combined}"
            };
            Process.Start(psi);
        }

        // Pattern 5: LINQ Join with tainted data
        public void JoinPattern(string userInput)
        {
            var parts = new[] { "echo", userInput, "done" };

            // DETECT: LINQ aggregation (Join) tunnels tainted data
            var command = string.Join(" && ", parts.Select(p => p));

            Process.Start("cmd.exe", $"/c {command}");
        }

        // Safe pattern (should NOT be flagged)
        public void SafeLinq()
        {
            var numbers = new List<int> { 1, 2, 3 };
            var doubled = numbers.Select(x => x * 2).ToList();
            Console.WriteLine(string.Join(", ", doubled));
        }
    }
}
