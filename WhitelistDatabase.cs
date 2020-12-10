using MySql.Data.MySqlClient;
using System;
using System.Collections.Generic;
using System.Data;
using TShockAPI;
using TShockAPI.DB;

namespace AntiProxy
{
    public class WhitelistDatabase
    {
        private IDbConnection _db;

        public WhitelistDatabase(IDbConnection db)
        {
            _db = db;

            var table = new SqlTable("AntiProxyWhitelists",
                new SqlColumn("IP", MySqlDbType.String, 16) { Primary = true },
                new SqlColumn("AssociatedName", MySqlDbType.Text, 40));

            var ctor = new SqlTableCreator(db,
                db.GetSqlType() == SqlType.Mysql
                ? new MysqlQueryCreator()
                : (IQueryBuilder)new SqliteQueryCreator());

            ctor.EnsureTableStructure(table);
        }

        public bool IsWhitelisted(string ip)
        {
            using (var reader = _db.QueryReader("SELECT * FROM AntiProxyWhitelists WHERE IP=@0", ip))
            {
                return reader.Read();
            }
        }

        public bool TryAddWhitelist(string ip, string name)
        {
            try
            {
                if (IsWhitelisted(ip))
                {
                    return true;
                }
                else
                {
                    return _db.Query("INSERT INTO AntiProxyWhitelists (IP, AssociatedName) VALUES (@0, @1)", ip, name) == 1;
                }
            }
            catch(Exception ex)
            {
                TShock.Log.ConsoleError(ex.ToString());
                return false;
            }
        }

        public bool TryRemoveWhitelist(string ip)
        {
            try
            {
                if (!IsWhitelisted(ip))
                {
                    return true;
                }
                else
                {
                    return _db.Query("DELETE FROM AntiProxyWhitelists WHERE IP=@0", ip) == 1;
                }
            }
            catch(Exception ex)
            {
                TShock.Log.ConsoleError(ex.ToString());
                return false;
            }
        }

        public IEnumerable<Whitelist> GetAllWhitelists()
        {
            List<Whitelist> ips = new List<Whitelist>();

            try
            {
                using (var reader = _db.QueryReader("SELECT * FROM AntiProxyWhitelists"))
                {
                    while (reader.Read())
                    {
                        ips.Add(new Whitelist(reader.Get<string>("IP"), reader.Get<string>("AssociatedName")));
                    }

                    return ips;
                }
            }
            catch(Exception ex)
            {
                TShock.Log.ConsoleError(ex.ToString());
                return null;
            }
        }
    }

    public class Whitelist
    {
        public string IP { get; private set; }
        public string AssociatedName { get; private set; }

        public Whitelist(string ip, string associatedName)
        {
            IP = ip;
            AssociatedName = associatedName;
        }

        public override string ToString()
        {
            return IP + " - \"" + AssociatedName + "\"";
        }
    }
}