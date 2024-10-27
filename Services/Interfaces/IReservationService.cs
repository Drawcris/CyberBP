using Trips.Models;

namespace TripsS.Services.Interfaces
{
    public interface IReservationService
    {
        void Delete(Reservation reservation);

        Task<List<Reservation>> GetAllAsync();
        ValueTask<Reservation?> GetByIdAsync(Guid? id);
        Task InsertAsync(Reservation reservation);
        Task SaveAsync();
        void Update(Reservation reservation);
        bool Exist(Reservation reservation);
    }
}
