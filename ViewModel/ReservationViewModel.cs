using Trips.Models;

namespace TripsS.ViewModel;
public enum Status
{
    Active,
    Cancelled,
    Completed
}


public class ReservationViewModel
{
    public Guid IdReservation { get; set; }
    public int IdClient { get; set; }
    public int IdTrip { get; set; }
    public int AmountOfPeople { get; set; }
    public DateTime ReservationDate { get; set; }
    public ClientViewModel? Client { get; set; }
    public TripViewModel? Trip { get; set; }
    public Status? Status { get; set; }


}
