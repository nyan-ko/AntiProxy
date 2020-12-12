using AntiProxy.Enums;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Timers;
using System.Threading.Tasks;
using Terraria;
using Terraria.Localization;
using TerrariaApi.Server;
using TShockAPI;

namespace AntiProxy
{
    [ApiVersion(2, 1)]
    public class AntiProxy : TerrariaPlugin
    {
        public override string Name => "AntiProxy";
        public override string Author => "nyan";

        public Verifier Verifier { get; private set; }
        public WhitelistDatabase Database { get; private set; }
        public Config Config { get; private set; }

        private Timer _connectionThrottler;
        private bool _allowConnection;

        public AntiProxy(Main game) : base(game)
        {
            Order = 0;
        }

        public override void Initialize()
        {
            Config = Config.Read();

            if (Config.ContactEmail != "<VALID_EMAIL_HERE>")
            {
                TShock.Log.ConsoleInfo($"[AntiProxy] Using email \"{Config.ContactEmail}\"");
            }
            else
            {
                TShock.Log.ConsoleError($"[AntiProxy] Detected placeholder email being used, will not run for this server insance. Please edit the AntiProxy config.");
                return;
            }

            Commands.ChatCommands.Add(new Command("antiproxy.admin", APCommand, "apwhitelist", "apwl"));

            Verifier = new Verifier(Config.ContactEmail);
            Database = new WhitelistDatabase(TShock.DB);

            // getipintel.net does not want more than 15 requests per minute (i.e. 1 per 4 seconds) so this timer
            // should allow us to stay safely under that threshold.
            _connectionThrottler = new Timer(4250); 
            _connectionThrottler.Elapsed += AllowNewConnection;
            _connectionThrottler.AutoReset = true;
            _connectionThrottler.Enabled = true;

            ServerApi.Hooks.ServerJoin.Register(this, OnJoin);
        }

        private async void OnJoin(JoinEventArgs args)
        {
            var client = Netplay.Clients[args.Who];
            string addr = client.Socket.GetRemoteAddress().ToString();
            string ip = addr.Substring(0, addr.IndexOf(':'));  // GetRemoteAddress() by itself includes the port which needs to be cut off

            // banned users connecting are already handled by tshock so their ips will never be checked
            if (!Config.CheckRegisteredForProxy && TShock.UserAccounts.GetUserAccountByName(client.Name) != null)
            {
                return;
            }

            // wait until a new request can be made to getipintel.net
            while (!_allowConnection)
            {
                await Task.Delay(100);
            }

            RiskType risk = await Verifier.GetProxyRiskAsync(ip);

            // kick medium risk ips, ban high (i.e. guaranteed proxy) ips
            // include their encoded ip in case it's a false positive
            if (risk != RiskType.Low)
            {
                if (Database.IsWhitelisted(ip))
                {
                    TShock.Log.ConsoleInfo($"Whitelisted IP {ip} allowed through.");
                    TShock.Log.Write($"Whitelisted IP {ip} allowed through.", TraceLevel.Info);
                    return;
                }
                TShock.Log.ConsoleInfo($"Risk: {risk} for IP: {ip}");
                TShock.Log.Write($"Risk: {risk} for IP: {ip}", TraceLevel.Info);

                if (risk == RiskType.High)
                {
                    TShock.Bans.AddBan(ip, client.Name, client.ClientUUID, "", "High risk of proxy.");
                }

                client.PendingTermination = true;
                //client.PendingTerminationApproved = true;
                NetMessage.SendData((int)PacketTypes.Disconnect, args.Who, -1, NetworkText.FromLiteral($"Disconnected: possible proxy. Contact server admins if you have questions; your code is {EncodeIP(ip)}."));
                args.Handled = true;
            }
        }

        private void APCommand(CommandArgs args)
        {
            var p = args.Player;

            Action<string, List<string>> info = (string help, List<string> lines) =>
            {
                p.SendInfoMessage(help);
                p.SendInfoMessage(string.Join("\n", lines));
            };

            string sub = args.Parameters.Count == 0 ? "help" : args.Parameters[0].ToLower();
            switch (sub)
            {
                case "help":
                    var cmds = new List<string>()
                    {
                        "add - Adds an ip, encoded or normal, to the antiproxy whitelist.",
                        "del - Deletes an ip from the whitelist.",
                        "list - Lists current whitelisted ips."
                    };

                    info("Command for handling anti-proxy whitelists.", cmds);
                    break;
                case "add":
                {
                    var help = new List<string>()
                    {
                        "Usage: add -e/-n <associated name>",
                        "-e - Adds an encoded IP (e.g. A3-4D-8C-14)",
                        "-n - Adds a normal IP (e.g. 127.0.0.1)",
                        "Associated name is optional with a 40 character limit."
                    };

                    if (args.Parameters.Count < 3)
                    {
                        info("Subcommand for whitelisting an ip.", help);
                    }
                    else
                    {
                        string ip = args.Parameters[2];
                        string name = "";

                        if (args.Parameters[1] == "-e")
                        {
                            ip = DecodeIP(ip)?.ToString();
                        }
                        else if (args.Parameters[1] != "-n")
                        {
                            info("Subcommand for whitelisting an ip.", help);
                        }

                        if (args.Parameters.Count > 3)
                        {
                            name = string.Join(" ", args.Parameters.Skip(3));
                        }

                        if (!IPAddress.TryParse(ip, out IPAddress unused))
                        {
                            p.SendErrorMessage($"Could not parse {ip} as an ip.");
                        }
                        if (!Database.TryAddWhitelist(ip, name))
                        {
                            p.SendErrorMessage("Could not complete database query.");
                        }
                        else
                        {
                            p.SendSuccessMessage($"Successfully whitelisted {ip} with " + (name == "" ? "no associated name." : $"associated name \"{name}\"."));
                        }
                    }
                }
                    break;
                case "del":
                {
                    var help = new List<string>()
                    {
                        "Usage: del -e/-n",
                        "-e - Removes an encoded IP (e.g. A3-4D-8C-14)",
                        "-n - Removes a normal IP (e.g. 127.0.0.1)"
                    };

                    if (args.Parameters.Count < 3)
                    {
                        info("Subcommand for removing an ip from the whitelist.", help);
                    }
                    else
                    {
                        string ip = args.Parameters[2];

                        if (args.Parameters[1] == "-e")
                        {
                            ip = DecodeIP(ip)?.ToString();
                        }
                        else if (args.Parameters[1] != "-n")
                        {
                            info("Subcommand for removing an ip from the whitelist..", help);
                        }

                        if (!IPAddress.TryParse(ip, out IPAddress unused))
                        {
                            p.SendErrorMessage($"Could not parse {ip} as an ip.");
                        }
                        if (!Database.TryRemoveWhitelist(ip))
                        {
                            p.SendErrorMessage("Could not complete database query.");
                        }
                        else
                        {
                            p.SendSuccessMessage($"Successfully removed {ip} from the whitelist.");
                        }
                    }
                }
                    break;
                case "list":
                {
                    if (!PaginationTools.TryParsePageNumber(args.Parameters, 1, p, out int pgN))
                    {
                        return;
                    }

                    var ips = Database.GetAllWhitelists();

                    PaginationTools.SendPage(p, pgN, ips.ToList(),
                        new PaginationTools.Settings
                        {
                            HeaderFormat = "IP Whitelist ({0}/{1})",
                            FooterFormat = "Type /apwhitelist list {0} for more.",
                            NothingToDisplayString = "There are currently no whitelisted IPs."
                        });
                }
                    break;
            }
        }

        private void AllowNewConnection(object source, ElapsedEventArgs args)
        {
            _allowConnection = true;
        }

        public static string EncodeIP(string ip)
        {
            if (!IPAddress.TryParse(ip, out IPAddress adr))
            {
                return "";
            }

            byte[] componentBytes = IPAddress.Parse(ip).GetAddressBytes();

            return BitConverter.ToString(componentBytes);
        }

        public static IPAddress DecodeIP(string encodedIp)
        {
            string[] encodedComp = encodedIp.Split('-');
            byte[] components = new byte[encodedComp.Length];

            for (int i = 0; i < encodedComp.Length; i++)
            {
                if (!byte.TryParse(encodedComp[i], NumberStyles.AllowHexSpecifier, null, out byte norm))
                {
                    return null;
                }
                components[i] = norm;
            }

            return new IPAddress(components);
        }
    }
}
