﻿using MySql.Data.MySqlClient;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Services;
using System.Web.Services.Protocols;
using System.Xml.Serialization;

namespace Folixame.Authentication.WebService
{
    /// <summary>
    /// Descripción breve de Users
    /// </summary>
    [WebService(Namespace = "http://folixa.me/")]
    [WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]
    [System.ComponentModel.ToolboxItem(false)]
    // Para permitir que se llame a este servicio web desde un script, usando ASP.NET AJAX, quite la marca de comentario de la línea siguiente. 
    // [System.Web.Script.Services.ScriptService]
    public class Users : System.Web.Services.WebService
    {
        public Security Security { get; set; }

        [WebMethod]
        public string HelloWorld()
        {
            MySql.Data.MySqlClient.MySqlConnection conn;
            string myConnectionString;
            string res = "";

            myConnectionString = "server=156.35.95.49;user id=folixameadmin;"+
                "persistsecurityinfo=True;database=fm_users;Pwd=folixando;";

            try
            {
                conn = new MySql.Data.MySqlClient.MySqlConnection();
                conn.ConnectionString = myConnectionString;
                conn.Open();
            }
            catch (MySql.Data.MySqlClient.MySqlException ex)
            {
                res = ex.Message;
            }

            return res;
        }

        private int LastProfileId()
        {
            int id = 0;
            MySqlConnection conn = NewConnection();
            MySqlCommand cmd = new MySqlCommand("SELECT id FROM Profiles ORDER BY id DESC LIMIT 1;", conn);
            MySqlDataReader rd = cmd.ExecuteReader();
            while (rd.Read())
            {
                id = rd.GetInt32(0);
            }

            return id;
        }

        [WebMethod]
        public string SignUp(String email, String password)
        {
            MySqlConnection conn = NewConnection();
            MySqlCommand cmd;

            // TODO: mejorar esto: salt, ect.
            var sha1 = new SHA1CryptoServiceProvider();
            var data = Encoding.ASCII.GetBytes(password);
            var sha1data = sha1.ComputeHash(data);
            //var hashedPassword = ASCIIEncoding.GetString(sha1data);
            //string res = System.Text.Encoding.ASCII.GetString(sha1data);

            try 
            {
                cmd = new MySqlCommand("INSERT INTO Profiles(id, first_name, last_name, bio) VALUES (DEFAULT, NULL, NULL, NULL)", conn);
                cmd.Prepare();
                cmd.ExecuteNonQuery();
                int profileId = LastProfileId();
            
                cmd = new MySqlCommand("INSERT INTO Users(id, email, username, password, join_date, Profiles_id, Permissions_id) "+
                    "VALUES (DEFAULT, @email, NULL, @sha1data, NOW(), @Profiles_id, 3)", conn);
                cmd.Prepare();
                cmd.Parameters.AddWithValue("@email", email);
                cmd.Parameters.AddWithValue("@sha1data", sha1data);
                cmd.Parameters.AddWithValue("@Profiles_id", profileId);
                cmd.ExecuteNonQuery();

            }
            catch (MySqlException ex)
            {
                Console.WriteLine("Error: {0}", ex.ToString());

            }
            finally
            {
                if (conn != null)
                {
                    conn.Close();
                }

            }
            return "OK";
        }

        [WebMethod]
        [SoapHeader("Security", Direction = SoapHeaderDirection.In)]
        public string Greet(String userName, String password)
        {
            MySqlConnection conn = NewConnection();

            

            MySqlCommand command = new MySqlCommand("", conn);

            if (Security != null &&
            Security.UserName != null && Security.UserName.Equals("WS-Security"))
                return "Authenticate User " + Security.UserName;
            return "Invalid User!!";
        }

        private MySqlConnection NewConnection()
        {
            string connectionString = "server=156.35.95.49;user id=folixameadmin;" +
                "persistsecurityinfo=True;database=fm_users;Pwd=folixando;";

            MySqlConnection conn = new MySqlConnection(connectionString);
            conn.Open();

            return conn;
        }
    }

    [XmlRoot(Namespace = "http://schemas.xmlsoap.org/ws/2002/04/secext")]
    public class Security : SoapHeader
    {
        public string UserName { set; get; }
        public string Password { set; get; } 
    }
        
}