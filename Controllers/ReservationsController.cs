using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AutoMapper;
using FluentValidation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Trips;
using Trips.Models;
using TripsS.Repositories.Interfaces;
using TripsS.Services.Interfaces;
using TripsS.ViewModel;
using Microsoft.AspNetCore.Authorization;
namespace TripsS.Controllers
{
    [Authorize(Roles = "Manager,Admin,Member")]
    public class ReservationsController : Controller
    {
        private readonly IReservationService _context;
        private readonly IValidator<ReservationViewModel> _reservationValidator;
        private readonly IMapper _mapper;

        
        public ReservationsController(IReservationService context, IValidator<ReservationViewModel> reservationValidator, IMapper mapper)
        {
            _context = context;
            _reservationValidator = reservationValidator;
            _mapper = mapper;
        }

        // GET: Reservations
        public async Task<IActionResult> Index()
        {
            var Reservations = await _context.GetAllAsync();
            var reservationViewModel = Reservations.Select(reservation => new ReservationViewModel
            {
                IdReservation = reservation.IdReservation,
                IdClient = reservation.IdClient,
                IdTrip = reservation.IdTrip,
                AmountOfPeople = reservation.AmountOfPeople,
                ReservationDate = reservation.ReservationDate
                
            }).ToList();
            return View(reservationViewModel);
        }



        // GET: Reservations/Create
        [Authorize(Roles = "Manager,Admin")]
        public IActionResult Create()
        {
            return View();
        }

        // POST: Reservations/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Manager,Admin")]
        public async Task<IActionResult> Create([Bind("IdReservation,IdClient,IdTrip,AmountOfPeople,ReservationDate,Status")] ReservationViewModel reservationViewModel)
        {
            var result = _reservationValidator.Validate(reservationViewModel);
            if (!result.IsValid)
            {
                foreach (var failure in result.Errors)
                {
                    ModelState.AddModelError(failure.PropertyName, failure.ErrorMessage);
                }
            }
            if (result.IsValid)
            {
                var reservation = _mapper.Map<ReservationViewModel, Reservation>(reservationViewModel);
                reservation.IdReservation = Guid.NewGuid();
                await _context.InsertAsync(reservation);
                await _context.SaveAsync();
                return RedirectToAction(nameof(Index));
            }

            
            return View(reservationViewModel);
        }

        // GET: Reservations/Edit/5
        [Authorize(Roles="Manager,Admin")]
        public async Task<IActionResult> Edit(Guid id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var reservation = await _context.GetByIdAsync(id);
            if (reservation == null)
            {
                return NotFound();
            }
            var reservationViewModel = _mapper.Map<Reservation, ReservationViewModel>(reservation);
            return View(reservationViewModel);
        }

        // POST: Reservations/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Manager,Admin")]
        public async Task<IActionResult> Edit(Guid id, [Bind("IdReservation,IdClient,IdTrip,AmountOfPeople,ReservationDate,Status")] ReservationViewModel reservationViewModel)
        {
            if (id != reservationViewModel.IdReservation)
            {
                return NotFound();
            }
            var result = _reservationValidator.Validate(reservationViewModel);
            if (!result.IsValid)
            {
                foreach (var failure in result.Errors)
                {
                    ModelState.AddModelError(failure.PropertyName, failure.ErrorMessage);
                }
            }
            if (result.IsValid)
            {
                var reservation = _mapper.Map<ReservationViewModel, Reservation>(reservationViewModel);
                try
                {
                    _context.Update(reservation);
                    await _context.SaveAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!ReservationExists(reservation.IdReservation))
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
            return View(reservationViewModel);
        }

        // GET: Reservations/Delete/5
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Delete(Guid? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var reservation = await _context.GetByIdAsync(id);

            if (reservation == null)
            {
                return NotFound();
            }
            var reservationViewModel = _mapper.Map<Reservation, ReservationViewModel>(reservation);
            return View(reservationViewModel);
        }
        [Authorize(Roles = "Admin")]
        // POST: Reservations/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(Guid id)
        {
            
            var reservation = await _context.GetByIdAsync(id);
            if (reservation != null)
            {
                _context.Delete(reservation);
            }

            await _context.SaveAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool ReservationExists(Guid id)
        {
            return _context.Exist(new Reservation { IdReservation = id });  
        }
    }
}
