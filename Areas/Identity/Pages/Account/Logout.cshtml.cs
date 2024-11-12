// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Trips;
using TripsS.Models;

namespace TripsS.Areas.Identity.Pages.Account
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ILogger<LogoutModel> _logger;
        private readonly TripContext _context;

        public LogoutModel(SignInManager<IdentityUser> signInManager, ILogger<LogoutModel> logger, TripContext context)
        {
            _signInManager = signInManager;
            _logger = logger;
            _context = context;
        }

        private async Task LogActivity(string userName, string actionDescription)
        {
            var activity = new UserActivity
            {
                UserName = userName,
                ActionDate = DateTime.Now,
                ActionDescription = actionDescription
            };
            _context.UserActivities.Add(activity);
            await _context.SaveChangesAsync();
        }

        public async Task<IActionResult> OnPost(string returnUrl = null)
        {
            await _signInManager.SignOutAsync();
            _logger.LogInformation("User logged out.");
            await LogActivity(User.Identity.Name, "Logged out");
            if (returnUrl != null)
            {
                return LocalRedirect(returnUrl);
            }
            else
            {
                // This needs to be a redirect so that the browser performs a new
                // request and the identity for the user gets updated.
                return RedirectToPage();
            }
        }
    }
}
