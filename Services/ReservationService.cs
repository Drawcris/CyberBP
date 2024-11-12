using Trips.Models;
using Trips;
using TripsS.Services.Interfaces;
using TripsS.Repositories.Interfaces;


namespace TripsS.Services
{
   
    public class ReservationService : IReservationService
    {
        private readonly IReservationRepository _context;

        public ReservationService(IReservationRepository context)
        {
            _context = context;
        }

        public Task<List<Reservation>> GetAllAsync()
        {
            return _context.GetAllAsync();
        }

        public ValueTask<Reservation?> GetByIdAsync(Guid? id)
        {
            return _context.GetByIdAsync(id);
        }

        public async Task InsertAsync(Reservation reservation)
        {
            await _context.InsertAsync(reservation);
        }

        public void Update(Reservation reservation)
        {
            _context.Update(reservation);
        }

        public void Delete(Reservation reservation)
        {
            _context.Delete(reservation);
        }

        public async Task SaveAsync()
        {
            await _context.SaveAsync();
        }

        public bool Exist(Reservation reservation)
        {
            return _context.Exist(reservation);
        }
    }
}
