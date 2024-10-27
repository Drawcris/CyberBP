namespace TripsS.Repositories;
using Trips.Models;
using TripsS.Repositories.Interfaces;
using Trips;
using Microsoft.EntityFrameworkCore;

public class ClientRepositorycs : IClientRepository
{
    private readonly TripContext _context;

    public ClientRepositorycs(TripContext context)
    {
        _context = context;
    }

    public void Delete(Client client)
    {
       _context.Clients.Remove(client);
    }

    public Task<List<Client>> GetAllAsync()
    {
        return _context.Clients.ToListAsync();
    }

    public ValueTask<Client?> GetById(int? id)
    {
        return _context.Clients.FindAsync(id);
    }

    public async Task InsertAsync(Client client)
    {
        await _context.Clients.AddAsync(client);
        await _context.SaveChangesAsync();
    }

    public async Task SaveAsync()
    {
        await _context.SaveChangesAsync();
    }

    public void Update(Client client)
    {
        _context.Clients.Update(client);
        
    }
    public bool Exist(Client client)
    {
        return _context.Clients.Any(e => e.IdClient == client.IdClient);
    }
}
