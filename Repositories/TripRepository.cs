namespace TripsS.Repositories;

using Microsoft.EntityFrameworkCore;
using Trips;
using Trips.Models;
using TripsS.Repositories.Interfaces;

public class TripRepository : ITripRepository
{
   private readonly TripContext _context;
  
    public TripRepository(TripContext context)
    {
         _context = context;
    }

    public Task<List<Trip>> GetAllAsync()
    {
        return _context.Trips.ToListAsync();
    }

    public ValueTask<Trip?> GetByIdAsync(int? id)
    {
        return _context.Trips.FindAsync(id);
    }
    
    public async Task InsertAsync(Trip trip)
    {
        await _context.Trips.AddAsync(trip);
        
    }

    public void Update(Trip trip)
    {
        _context.Trips.Update(trip);
    }
    public void Delete(Trip trip)
    {
        _context.Trips.Remove(trip);
    }

    public async Task SaveAsync()
    {
        await _context.SaveChangesAsync();
    }
    public bool Exist(Trip client)
    {
        return _context.Trips.Any(e => e.IdTrip == client.IdTrip);
    }




}
