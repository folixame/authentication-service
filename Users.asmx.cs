using MySql.Data.MySqlClient;
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
        [SoapHeader("Security", Direction = SoapHeaderDirection.In)]
        public string SignUp()
        {
            MySqlConnection conn = NewConnection();
            MySqlCommand cmd;

            // TODO: mejorar esto: salt, ect.
            //var sha1 = new SHA1CryptoServiceProvider();
            //var data = Encoding.ASCII.GetBytes(password);
            //var sha1data = sha1.ComputeHash(data);

            if (Security != null && Security.Email != null && Security.Password != null)
            {
                var sha1data = Encoding.ASCII.GetBytes(Security.Password);

                try
                {
                    cmd = new MySqlCommand("INSERT INTO Profiles(id, first_name, last_name, bio) VALUES (DEFAULT, NULL, NULL, NULL)", conn);
                    cmd.Prepare();
                    cmd.ExecuteNonQuery();
                    int profileId = LastProfileId();

                    cmd = new MySqlCommand("INSERT INTO Users(id, email, username, password, join_date, Profiles_id, Permissions_id) " +
                        "VALUES (DEFAULT, @email, NULL, @sha1data, NOW(), @Profiles_id, 3)", conn);
                    cmd.Prepare();
                    cmd.Parameters.AddWithValue("@email", Security.Email);
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
            }
            //var hashedPassword = ASCIIEncoding.GetString(sha1data);
            //string res = System.Text.Encoding.ASCII.GetString(sha1data);
            
            return "OK";
        }

        [WebMethod]
        [SoapHeader("Security", Direction = SoapHeaderDirection.In)]
        public string LogIn()
        {
            MySqlConnection conn = NewConnection();
            MySqlCommand cmd;
            byte[] sha1data = null;
            string password = "";

            //var hashedPassword = ASCIIEncoding.GetString(sha1data);
            //string res = System.Text.Encoding.ASCII.GetString(sha1data);

            try
            {
                cmd = new MySqlCommand("SELECT password FROM Users WHERE email = \"" + Security.Email + "\"", conn);
                MySqlDataReader rd = cmd.ExecuteReader();
                while (rd.Read())
                {
                    sha1data = (byte[]) rd["password"];
                }
                if (sha1data != null)
                {
                    password = System.Text.Encoding.ASCII.GetString(sha1data).Trim('\0'); // TODO evitar esta chapuza
                }
                else
                {
                    return "Invalid User!! " + Security.Password;
                }

                if (Security != null && Security.Email != null && Security.Password == password)
                {
                    return "Authenticate User " + Security.Email;
                }
                    
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

            return "Invalid User!! "+ Security.Password;
        }

        public bool userExist(string inputEmail, string inputPassword)
        {
            MySqlConnection conn = NewConnection();
            MySqlCommand cmd;
            byte[] sha1data = null;
            string password = "";

            try
            {
                cmd = new MySqlCommand("SELECT password FROM Users WHERE email = \"" + inputEmail + "\"", conn);
                MySqlDataReader rd = cmd.ExecuteReader();
                while (rd.Read())
                {
                    sha1data = (byte[])rd["password"];
                }
                if (sha1data != null)
                {
                    password = System.Text.Encoding.ASCII.GetString(sha1data).Trim('\0'); // TODO evitar esta chapuza
                }
                else
                {
                    return false;
                }
                if (Security != null && inputEmail != null && inputPassword == password)
                {
                    return true;
                }
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

            return false;
        }

        [WebMethod]
        [SoapHeader("Security", Direction = SoapHeaderDirection.In)]
        public string Delete()
        {
            MySqlConnection conn = NewConnection();
            MySqlCommand cmd;

            if (userExist(Security.Email, Security.Password))
            {
                try
                {
                    cmd = new MySqlCommand("DELETE FROM Users WHERE email = @email", conn);
                    MySqlParameter param = new MySqlParameter("@email", Security.Email);
                    cmd.Parameters.Add(param);
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
            }

            return "Invalid User!! " + Security.Email;
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
        public string Email { set; get; }
        public string Password { set; get; } 
    }
        
}
