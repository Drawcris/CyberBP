namespace TripsS.ViewModel;
using TripsS.Validator;

public class ClientViewModel
{
    public int IdClient { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public int? Pesel { get; set; }
    public string Email { get; set; }
    public string? Phone { get; set; }
  
    public IEnumerable<ReservationViewModel>? Reservations { get; set; }
}
