using AntiProxy.Enums;
using System.Diagnostics;
using System.IO;
using Terraria;
using Terraria.Localization;
using TerrariaApi.Server;
using TShockAPI;

namespace AntiProxy
{
    [ApiVersion(2, 1)]
    public class AntiProxy : TerrariaPlugin
    {
        public static readonly string EmailTxt = Path.Combine(TShock.SavePath, "antiproxy-email.txt");

        public override string Name => "AntiProxy";
        public override string Author => "nyan";

        public Verifier Verifier { get; private set; }

        public AntiProxy(Main game) : base(game)
        {
            Order = 0;
        }

        public override void Initialize()
        {
            string email;
            if (File.Exists(EmailTxt))
            {
                email = File.ReadAllText(EmailTxt);
                TShock.Log.ConsoleInfo($"[AntiProxy] Using email \"{email}\"");
            }
            else
            {
                File.WriteAllText(EmailTxt, "<VALID_EMAIL_HERE>");
                TShock.Log.ConsoleError($"AntiProxy could not find a stored email. A placeholder has been created at {EmailTxt}, however AntiProxy will not run for this server instance.");
                return;
            }

            Verifier = new Verifier(email);

            ServerApi.Hooks.ServerJoin.Register(this, OnJoin);
        }

        private async void OnJoin(JoinEventArgs args)
        {
            var client = Netplay.Clients[args.Who];
            string addr = client.Socket.GetRemoteAddress().ToString().ToString();
            string ip = addr.Substring(0, addr.IndexOf(':'));
            RiskType risk = await Verifier.GetProxyRiskAsync(ip);

            if (risk != RiskType.Low)
            {
                TShock.Log.ConsoleInfo($"Risk: {risk} for IP: {ip}");
                TShock.Log.Write($"Risk: {risk} for IP: {ip}", TraceLevel.Info);

                client.PendingTermination = true;
                //client.PendingTerminationApproved = true;
                NetMessage.SendData((int)PacketTypes.Disconnect, args.Who, -1, NetworkText.FromLiteral("Disconnected: possible proxy. Contact server admins if you have questions."));
                args.Handled = true;
            }
        }
    }
}
