using System;
namespace TripsS.Models 
{
    public class UserActivity
    {
        public int Id { get; set; }
        public string UserName { get; set; }
        public DateTime ActionDate { get; set; }
        public string ActionDescription { get; set; }
    }
}
