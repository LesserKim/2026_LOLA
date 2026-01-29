using System;
using System.Collections.Generic;
using System.Text;
using System.Diagnostics;
using System.Collections.Concurrent;

// 부모 추적을 전담.
namespace LotlDetector
{
    public class ProcessMapper
    {
        private ConcurrentDictionary<int, string> _map = new();

        public ProcessMapper()
        {
            foreach (var p in Process.GetProcesses())
            {
                _map[p.Id] = p.ProcessName;
            }
        }

        public void Add(int pid, string name) => _map[pid] = name;
        public void Remove(int pid) => _map.TryRemove(pid, out _);
        public string GetParentName(int ppid) => _map.TryGetValue(ppid, out var name) ? name : "Unknown";
        
    }
}
