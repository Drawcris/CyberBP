using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;


namespace Trips.Models
{
    public enum Status
    {
        Active,
        Cancelled,
        Completed
    }
    
        
    
    public class Reservation
    {

        [Key]
        public Guid IdReservation { get; set; }
        public int IdClient { get; set; }
        public int IdTrip { get; set; }
        public int AmountOfPeople { get; set; }
        public DateTime ReservationDate { get; set; }
        public Client? Client { get; set; }
        public Trip? Trip { get; set; }
        public Status? Status { get; set; }


    }
}
