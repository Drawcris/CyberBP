// HomeController.cs

using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Linq;
using Trips;


public class HomeController : Controller
{
    private readonly TripContext _context;

    public HomeController(TripContext context)
    {
        _context = context;
    }

    public IActionResult Index()
    {
        var students = _context.Clients.ToList(); // Lista student�w
        var wycieczki = _context.Trips.ToList(); // Lista wycieczek
        var rezerwacje = _context.Reservations.Include(r => r.Client).Include(r => r.Trip).ToList(); // Lista rezerwacji

        ViewBag.Wycieczki = wycieczki;
        ViewBag.Rezerwacje = rezerwacje;

        return View(students);
    }

    public IActionResult Trips()
    {
        var wycieczki = _context.Trips.ToList(); // Lista wycieczek
        return View(wycieczki);
    }
    public IActionResult Clients()
    {


        return View("Views/Clients/Index.cshtml");
    }
}