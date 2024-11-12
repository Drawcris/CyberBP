using Trips;
using Trips.Models;
using TripsS.Repositories.Interfaces;
using TripsS.Services.Interfaces;

namespace TripsS.Services
{
    public class TripService : ITripService
    {
        private readonly ITripRepository _context;

        public TripService(ITripRepository context)
        {
            _context = context;
        }

        public Task<List<Trip>> GetAllAsync()
        {
            return _context.GetAllAsync();
        }

        public ValueTask<Trip?> GetByIdAsync(int? id)
        {
            return _context.GetByIdAsync(id);
        }

        public async Task InsertAsync(Trip trip)
        {
            await _context.InsertAsync(trip);

        }

        public void Update(Trip trip)
        {
            _context.Update(trip);
        }
        public void Delete(Trip trip)
        {
            _context.Delete(trip);
        }

        public async Task SaveAsync()
        {
            await _context.SaveAsync();
        }
        public bool Exist(Trip client)
        {
            return _context.Exist(client);
        }
    }
}
