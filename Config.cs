using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using Newtonsoft.Json;
using TShockAPI;
using System.Text;
using System.Threading.Tasks;

namespace AntiProxy
{
    public class Config
    {
        private static string FilePath = Path.Combine(TShock.SavePath, "antiproxy-config.json");

        public string ContactEmail { get; set; }
        public bool CheckRegisteredForProxy { get; set; }

        private Config() { }

        public static Config Read()
        {
            Config cfg;
            if (!File.Exists(FilePath))
            {
                cfg = new Config()
                {
                    ContactEmail = "<VALID_EMAIL_HERE>",
                    CheckRegisteredForProxy = false
                };

                cfg.Write();
                return cfg;
            }
            else
            {
                cfg = JsonConvert.DeserializeObject<Config>(FilePath);
                return cfg;
            }
        }

        public void Write()
        {
            File.WriteAllText(FilePath, JsonConvert.SerializeObject(this));
        }
    }
}
