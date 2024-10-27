namespace TripsS.Repositories;
using Trips.Models;
using TripsS.Repositories.Interfaces;
using Trips;
using Microsoft.EntityFrameworkCore;

public class ReservationRepositorycs : IReservationRepository
{
    private readonly TripContext _context;

    public ReservationRepositorycs(TripContext context)
    {
        _context = context;
    }

    public Task<List<Reservation>> GetAllAsync()
    {
       return _context.Reservations.ToListAsync();
    }

    public ValueTask<Reservation?> GetByIdAsync(Guid? id)
    {
        return _context.Reservations.FindAsync(id);
    }

    public async Task InsertAsync(Reservation reservation)
    {
        await _context.Reservations.AddAsync(reservation);
    }

    public void Update(Reservation reservation)
    {
        _context.Reservations.Update(reservation);
    }

    public void Delete(Reservation reservation)
    {
        _context.Reservations.Remove(reservation);
    }

    public async Task SaveAsync()
    {
        await _context.SaveChangesAsync();
    }

    public bool Exist(Reservation reservation)
    {
        return _context.Reservations.Any(e => e.IdReservation == reservation.IdReservation);
    }

   
}
