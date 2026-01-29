using Microsoft.Diagnostics.Tracing.Parsers.MicrosoftWindowsTCPIP;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Timers;

namespace LotlDetector
{
    public class Logger
    {
        private static string logPath = "DetectionLog.txt";
        public static void WriteLog(string img, string parent, string cmd, string decoded, int score)
        {
            string logEntity = $@"
            [Time]: {DateTime.Now:yyyy-MM-dd HH: mm: ss} 
            [status] : Blocked
            [Process]: {img}
            [Parent Process]: {parent}
            [Command Line]: {cmd} 
            [score] : {score}
            [result] : {(string.IsNullOrEmpty(decoded) ? "N/A":decoded)}
           ---------------------------------------------- ";

            try
            {
                File.AppendAllText(logPath, logEntity + Environment.NewLine);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Log Save Failed : {ex.Message}");
            }
        }
    }
}
