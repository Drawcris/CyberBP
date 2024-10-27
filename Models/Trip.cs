using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Trips.Models
{
    public class Trip
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int IdTrip { get; set; }
        public string From { get; set; }
        public string To { get; set; }
        public DateTime StartTrip { get; set; }
        public DateTime EndTrip { get; set; }
        public int Price { get; set; }
        public IEnumerable<Reservation>? Reservations { get; set;}
    }
}
