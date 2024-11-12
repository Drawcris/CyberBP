namespace TripsS.Repositories.Interfaces;

using System.Collections.Generic;
using System.Threading.Tasks;
using Trips.Models;

public interface IClientRepository
{
    Task<List<Client>> GetAllAsync();
    ValueTask<Client?> GetById(int? id);
    Task InsertAsync(Client client);
    void Update(Client client);
    void Delete(Client client);
    Task SaveAsync();
    bool Exist(Client reservation);
}
