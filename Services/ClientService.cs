namespace TripsS.Services;

using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.Threading.Tasks;
using Trips.Models;
using TripsS.Repositories.Interfaces;
using TripsS.Services.Interfaces;
using TripsS.Repositories;  

public class ClientService : IClientService
{
    private readonly IClientRepository _clientRepository;

    public ClientService(IClientRepository clientRepository)
    {
        this._clientRepository = clientRepository;
    }
    public void Delete(Client client)
    {
       _clientRepository.Delete(client);
    }

    public bool Exist(Client client)
    {
        return _clientRepository.Exist(client);
    }

    public async Task<List<Client>> GetAllAsync()
    {
        return await _clientRepository.GetAllAsync();
    }

    public async ValueTask<Client?> GetByIdAsync(int? id)
    {
        return await _clientRepository.GetById(id);
    }

    public async Task InsertAsync(Client client)
    {
        await _clientRepository.InsertAsync(client);
    }

    public async Task SaveAsync()
    {
        await _clientRepository.SaveAsync();
    }

    public void Update(Client client)
    {
         _clientRepository.Update(client);
    }
}
