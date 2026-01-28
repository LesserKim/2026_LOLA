// See https://aka.ms/new-console-template for more information
//Console.WriteLine("Hello, World!");

using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using System.Collections.Concurrent;

//Process Map (Memory the name)
ConcurrentDictionary<int, string> processMap = new ConcurrentDictionary<int, string>();

foreach (var p in System.Diagnostics.Process.GetProcesses())
{
    processMap[p.Id] = p.ProcessName;
}

string sessionName = "Advanced-EDR_Session";

using (var session = new TraceEventSession(sessionName))
{
    session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);
    session.Source.Kernel.ProcessStart += (data) =>
    {
        //new Process
        processMap[data.ProcessID] = data.ImageFileName;

        //ParentName , trygetvalue() => 지정한 키와 연결된 값을 가져옴 
        processMap.TryGetValue(data.ParentID, out string parentName);
        parentName ??= "Unknown/Terminared";

        //Danger Score
        int riskScore = 0;
        List<string> detectionReasons = new List<string>();

        string cmd = data.CommandLine?.ToLower() ?? "";
        string img = data.ImageFileName.ToLower();
        string pName = parentName.ToLower();

        //위험한 부모와 자식관계
        if ((pName.Contains("winword") || pName.Contains("excel")) && (img.Contains("powershell") || img.Contains("cmd")))
        {
            riskScore += 60;
            detectionReasons.Add("Office document spawns a shell");
        }

        // 인코딩된 명령어 
        if (cmd.Contains("-enc") || cmd.Contains("-encodedcommand"))
        {
            riskScore += 40;
            detectionReasons.Add("Encoded command Line detected");
        }

        // 외부 파일 다운시도  
        if (cmd.Contains("downloadstring") || cmd.Contains("http") || img.Contains("certutil"))
        {
            riskScore += 50;
            detectionReasons.Add("External Download attempt detected");
        }

        //detection score result
        if (riskScore > 0)
        {
            PrintDetection(data, parentName, riskScore, detectionReasons);
        }
    };

    session.Source.Kernel.ProcessStop += (data) =>
    {
        processMap.TryRemove(data.ProcessID, out _);
    };

    Console.WriteLine("LotL Detection is running");
    session.Source.Process();
}

