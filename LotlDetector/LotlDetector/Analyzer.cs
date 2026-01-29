using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace LotlDetector
{
    public class Analyzer
    {
        public string DecodePowerShell(string commandLine) 
        {
            if (string.IsNullOrEmpty(commandLine))
                return "";

            var match = Regex.Match(commandLine, @"-(?:e|en|enc|encodedcommand)\s+([A-Za-z0-9+/=]+)", RegexOptions.IgnoreCase);

            if (match.Success)
            {
                try
                {
                    string base64Str = match.Groups[1].Value;
                    byte[] data = Convert.FromBase64String(base64Str);
                    return Encoding.Unicode.GetString(data);
                }
                catch { return "[Decoding Failed]"; }
            }
            return "";
        }

        public int CalculateScore (string img, string parent, string cmd, out List<string> reasons)
        {
            int score = 0;
            reasons = new List<string>();

            // 비정상적인 부모 프로세스 
            if (parent.ToLower().Contains("winword") || parent.ToLower().Contains("excel"))
            {
                score += 50;
                reasons.Add("비정상적 부모 프로세스");
            }

            // 인코딩 시도 시 
            if (cmd.ToLower().Contains("-enc"))
            {
                score += 30;
                reasons.Add("명령어 은닉 시도 (-enc)");
            }
            return score;
        }
    }
}
