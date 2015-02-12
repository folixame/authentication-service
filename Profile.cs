using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Folixame.Authentication.WebService
{
    public class Profile
    {
        public Profile() { }
        public Profile(int id, string firstName, string lastName, string bio)
        {
            this.id = id;
            this.firstName = firstName;
            this.lastName = lastName;
            this.bio = bio;
        }
        public int id { get; set; }
        public string firstName {get;set;}
        public string lastName { get; set; }
        public string bio { get; set; }
    }
}