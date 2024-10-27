using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Trips.Models
{
    public class Client
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int IdClient { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public int? Pesel { get; set; }
        public string Email { get; set; }
        public string? Phone { get; set; }

        public IEnumerable<Reservation>? Reservations { get; set; }

    }
}
