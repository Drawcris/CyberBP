using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Trips;
using Trips.Models;
using TripsS.Repositories;
using TripsS.Repositories.Interfaces;   
using TripsS.Services.Interfaces;
using TripsS.ViewModel;
using TripsS.Validator;
using System.ComponentModel.DataAnnotations;
using FluentValidation;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;


namespace Trips.Controllers
{
    [Authorize(Roles = "Manager,Admin")]
    public class ClientsController : Controller
    {


        private readonly IClientService _clientServices;
        private readonly IValidator<ClientViewModel> _clientValidator;
        private readonly IMapper _mapper;
        private readonly TripContext _context;
        public ClientsController(IClientService clientRepository, IValidator<ClientViewModel> clientValidator , IMapper mapper, TripContext context)
        {
            this._clientServices = clientRepository;
            _clientValidator = clientValidator;
            _mapper = mapper;
            _context = context;

        }

        public async Task<IActionResult> UserActivities()
        {
            var activities = await _context.UserActivities.ToListAsync();
            return View(activities);
        }

        public async Task<IActionResult> Index()
        {
            var clients = await _clientServices.GetAllAsync();

            var clientsList = _mapper.Map<List<Client>, List<ClientViewModel>>(clients);

            return View(clientsList);
        }

        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var client = await _clientServices.GetByIdAsync(id);
            if (client == null)
            {
                return NotFound();
            }
            var clientViewModel = _mapper.Map<Client, ClientViewModel>(client);

            return View(clientViewModel);
        }
        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task <IActionResult> Create([Bind("IdClient,FirstName,LastName,Pesel,Email,Phone")] ClientViewModel clientViewModel)
        {
            var _clientValidatorR = _clientValidator.Validate(clientViewModel);
            if (_clientValidatorR.IsValid)
            {
                var client = _mapper.Map<ClientViewModel, Client>(clientViewModel);
                await _clientServices.InsertAsync(client);
                await _clientServices.SaveAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(clientViewModel);
        }

        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var client = await _clientServices.GetByIdAsync(id);
            if (client == null)
            {
                return NotFound();
            }
            var clientViewModel = new ClientViewModel
            {
                IdClient = client.IdClient,
                FirstName = client.FirstName,
                LastName = client.LastName,
                Email = client.Email,
                Phone = client.Phone
            };
            return View(clientViewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
            public async Task <IActionResult> Edit(int id, [Bind("IdClient,FirstName,LastName,Pesel,Email,Phone")] ClientViewModel clientViewModel)
            {
                if (id != clientViewModel.IdClient)
                {
                    return NotFound();
                }
            var result= _clientValidator.Validate(clientViewModel);
            if (!result.IsValid)
            {
                foreach (var failure in result.Errors)
                {
                    ModelState.AddModelError(failure.PropertyName, failure.ErrorMessage);
                }
            }
            if (result.IsValid)
            {
                    var client = _mapper.Map<ClientViewModel, Client>(clientViewModel);
                    try
                    {
                        _clientServices.Update(client);
                        await _clientServices.SaveAsync();
                    }
                    catch (DbUpdateConcurrencyException)
                    {
                        if (!ClientExists(client.IdClient))
                        {
                            return NotFound();
                        }
                        else
                        {
                            throw;
                        }
                    }
                    return RedirectToAction(nameof(Index));
                } 


                return View(clientViewModel);
            
               
            }

        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var client = await _clientServices.GetByIdAsync(id);
            var clientViewModel = _mapper.Map<Client, ClientViewModel>(client);

            if (client == null)
            {
                return NotFound();
            }

            return View(clientViewModel);
        }

        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]

        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var client = await _clientServices.GetByIdAsync(id);
            if (client != null)
            {
                _clientServices.Delete(client);
            }

            await _clientServices.SaveAsync();
            return RedirectToAction(nameof(Index));
        }
        
        private bool ClientExists(int id)
        {
            return _clientServices.Exist(new Client { IdClient = id });
        }

    }
}
