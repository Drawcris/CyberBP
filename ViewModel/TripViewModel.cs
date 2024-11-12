using Trips.Models;

namespace TripsS.ViewModel;

public class TripViewModel
{
    public int IdTrip { get; set; }
    public string From { get; set; }
    public string To { get; set; }
    public DateTime StartTrip { get; set; }
    public DateTime EndTrip { get; set; }
    public int Price { get; set; }
    public IEnumerable<ReservationViewModel>? Reservations { get; set; }
}
