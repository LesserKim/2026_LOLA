using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using LotlDetector;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

var mapper = new ProcessMapper();
var analyzer = new Analyzer();
string sessionName = "LotL-EDR";

//커널 이벤트 세션 
using (var session = new TraceEventSession(sessionName))
{
    session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);

    session.Source.Kernel.ProcessStart += (Data) =>
    {
        mapper.Add(Data.ProcessID, Data.ImageFileName);
        string pName = mapper.GetParentName(Data.ParentID);

        int score = analyzer.CalculateScore(Data.ImageFileName, pName, Data.CommandLine, out List<string> reasons);
        string decodedCmd = analyzer.DecodePowerShell(Data.CommandLine);

        if (score > 0)
        {
            PrintAlert(Data.ImageFileName, pName, Data.CommandLine, decodedCmd, score, reasons);
        }
    };

    session.Source.Kernel.ProcessStop += (data) =>
    {
        mapper.Remove(data.ProcessID);
    };

    Console.WriteLine("Monitoring...");
    session.Source.Process();
}

static void PrintAlert(string img, string parent, string cmd, string decoded, int score, List<string> reasons)
{
    Console.ForegroundColor = score >= 80 ? ConsoleColor.Red : ConsoleColor.Yellow;
    Console.WriteLine($"Detection : Score : {score}");
    Console.ResetColor();

    Console.WriteLine($"Process : {img}");
    Console.WriteLine($"Parent : {parent}");
    Console.WriteLine($"cmd : {cmd}");

    if(!string.IsNullOrEmpty(decoded)){
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"decoding result = {decoded}");
        Console.ResetColor();
    }

    Console.WriteLine("Detection Source");
    foreach (var r in reasons) Console.WriteLine($"    L {r}");
    Console.WriteLine(new string('-', 50));
    
}

