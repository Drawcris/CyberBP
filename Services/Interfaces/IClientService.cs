namespace TripsS.Services.Interfaces;
using System.Collections.Generic;
using Trips.Models;

public interface IClientService
{
     Task<List<Client>> GetAllAsync();
     ValueTask<Client?> GetByIdAsync(int? id);
     Task InsertAsync(Client client);
     void Update(Client client);
     void Delete(Client client);
     Task SaveAsync();
     bool Exist(Client client);

}
