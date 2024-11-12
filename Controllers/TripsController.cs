using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AutoMapper;
using FluentValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Trips;
using Trips.Models;
using TripsS.Repositories.Interfaces;
using TripsS.Services.Interfaces;
using TripsS.ViewModel;

namespace Trips.Controllers
{
    [AllowAnonymous]
    public class TripsController : Controller
    {
        private readonly ITripService _context;
        private readonly IValidator<TripViewModel> _tripValidator;
        private readonly IMapper _mapper;
        public TripsController(ITripService context, IValidator<TripViewModel> tripValidator , IMapper mapper)
        {
            this._context = context;
            _tripValidator = tripValidator;
            _mapper = mapper;
        }

        // GET: Trips
        public async Task<IActionResult> Index()
        {
            var Trips = await _context.GetAllAsync();
            var TripsList = _mapper.Map<List<Trip>, List<TripViewModel>>(Trips);

            return View( TripsList);
        }

        //// GET: Trips/Details/5
        //public async Task<IActionResult> Details(int? id)
        //{
        //    if (id == null)
        //    {
        //        return NotFound();
        //    }

        //    var trip = await _context.Trips
        //        .FirstOrDefaultAsync(m => m.IdTrip == id);
        //    if (trip == null)
        //    {
        //        return NotFound();
        //    }

        //    return View(trip);
        //}

        // GET: Trips/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Trips/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("IdTrip,From,To,StartTrip,EndTrip,Price")] TripViewModel tripViewModel)
        {
           var result = _tripValidator.Validate(tripViewModel);
            if (!result.IsValid)
            {
                foreach (var failure in result.Errors)
                {
                    ModelState.AddModelError(failure.PropertyName, failure.ErrorMessage);
                }
            }
           if(result.IsValid)
            {
                var trip = _mapper.Map<TripViewModel, Trip>(tripViewModel);
                await _context.InsertAsync(trip);
                await _context.SaveAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(tripViewModel);
        }

        // GET: Trips/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var trip = await _context.GetByIdAsync(id);
            if (trip == null)
            {
                return NotFound();
            }

            //Mapowanie Trip na TripViewModel
            var tripViewModel = _mapper.Map<Trip, TripViewModel>(trip);
            return View(tripViewModel);
        }

        // POST: Trips/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("IdTrip,From,To,StartTrip,EndTrip,Price")] TripViewModel tripViewModel)
        {
            if (id != tripViewModel.IdTrip)
            {
                return NotFound();
            }

            var result = _tripValidator.Validate(tripViewModel);
            if (!result.IsValid)
            {
                foreach (var failure in result.Errors)
                {
                    ModelState.AddModelError(failure.PropertyName, failure.ErrorMessage);
                }
            }
            if (result.IsValid)
            {
                var trip = _mapper.Map<TripViewModel, Trip>(tripViewModel);
                try
                {
                    _context.Update(trip);
                    await _context.SaveAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!TripExists(trip.IdTrip))
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
            return View(tripViewModel);
        }

        // GET: Trips/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var trip = await _context.GetByIdAsync(id);
                
            if (trip == null)
            {
                return NotFound();
            }

            return View(trip);
        }

        // POST: Trips/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var trip = await _context.GetByIdAsync(id);
            if (trip != null)
            {
                _context.Delete(trip);
            }

            await _context.SaveAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool TripExists(int id)
        {
            return _context.Exist(new Trip { IdTrip = id});
        }

        
    }
}
