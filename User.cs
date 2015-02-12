using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Folixame.Authentication.WebService
{
    public class User
    {
        public User(int id, string email, string username, string password, string joinDate, Profile profile, int permissions)
        {
            this.id = id;
            this.email = email;
            this.username = username;
            this.password = password;
            this.joinDate = joinDate;
            this.profile = profile;
            this.permissions = permissions;
        }
        public int id { get; set; }
        public string email { get; set; }
        public string username { get; set; }
        public string password { get; set; }
        public string joinDate { get; set; }
        public Profile profile { get; set; }
        public int permissions { get; set; }
    }
}