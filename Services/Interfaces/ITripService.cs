using Trips.Models;

namespace TripsS.Services.Interfaces;

public interface ITripService
{
    Task<List<Trip>> GetAllAsync();
    ValueTask<Trip?> GetByIdAsync(int? id);
    Task InsertAsync(Trip trip);
    void Update(Trip trip);
    void Delete(Trip trip);
    Task SaveAsync();
    bool Exist(Trip trip);
}
