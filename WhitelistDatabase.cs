using System.Data;
using System.Data.Sql;
using TShockAPI;
using System.Data.Common;
using MySql.Data.MySqlClient;
using System;
using TShockAPI.DB;
using System.Collections.Generic;

namespace AntiProxy
{
    public class WhitelistDatabase
    {
        private IDbConnection _db;

        public WhitelistDatabase(IDbConnection db)
        {
            _db = db;

            var table = new SqlTable("AntiProxyWhitelists",
                new SqlColumn("IP", MySqlDbType.String, 16) { Primary = true });

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

        public bool TryAddWhitelist(string ip)
        {
            try
            {
                if (IsWhitelisted(ip))
                {
                    return true;
                }
                else
                {
                    return _db.Query("INSERT INTO AntiProxyWhitelists (IP) VALUES (@0);", ip) == 1;
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
                    return _db.Query("DELETE FROM AntiProxyWhitelist WHERE IP=@0", ip) == 1;
                }
            }
            catch(Exception ex)
            {
                TShock.Log.ConsoleError(ex.ToString());
                return false;
            }
        }

        public IEnumerable<string> GetAllWhitelists()
        {
            List<string> ips = new List<string>();

            try
            {
                using (var reader = _db.QueryReader("SELECT * FROM AntiProxyWhitelists"))
                {
                    while (reader.Read())
                    {
                        ips.Add(reader.Get<string>("IP"));
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
}