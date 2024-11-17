using Microsoft.AspNetCore.Identity;

namespace TripsS.Models
{
    public class ApplicationUser : IdentityUser
    {
        public DateTime? PasswordExpirationDate { get; set; }
        public DateTime? LastPasswordChangeDate { get; set; }
        public bool MustChangePassword { get; set; }
    }
}
