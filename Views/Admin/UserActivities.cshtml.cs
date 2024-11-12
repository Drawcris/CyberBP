using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.Threading.Tasks;
using Trips;
using TripsS.Models;

[Authorize(Roles = "Admin")]
public class UserActivitiesModel : PageModel
{
    private readonly TripContext _context;

    public UserActivitiesModel(TripContext context)
    {
        _context = context;
    }

    public IList<UserActivity> UserActivities { get; set; }

    public async Task OnGetAsync()
    {
        UserActivities = await _context.UserActivities.ToListAsync();
    }
}