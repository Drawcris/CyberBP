namespace TripsS.Repositories.Interfaces;

using System.Collections.Generic;
using System.Threading.Tasks;
using Trips.Models;
using Microsoft.EntityFrameworkCore;


public interface IReservationRepository
{
    void Delete(Reservation reservation);

    Task<List<Reservation>> GetAllAsync();
    ValueTask<Reservation?> GetByIdAsync(Guid? id);
    Task InsertAsync(Reservation reservation);
    Task SaveAsync();
    void Update(Reservation reservation);
    bool Exist(Reservation reservation);
}