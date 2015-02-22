using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Folixame.Authentication.WebService
{
    public class Favourite
    {
        public Favourite() { }
        public Favourite(int id, int userId, int eventId)
        {
            this.id = id;
            this.userId = userId;
            this.eventId = eventId;
        }
        public int id { get; set; }
        public int userId { get; set; }
        public int eventId { get; set; }
    }
}