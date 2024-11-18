using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using TripsS.Models;

namespace TripsS.Areas.Identity.Pages.Account
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<LoginModel> _logger;
        private readonly Trips.TripContext _context;

        public LoginModel(SignInManager<ApplicationUser> signInManager, ILogger<LoginModel> logger, Trips.TripContext context, UserManager<ApplicationUser> userManager)
        {
            _signInManager = signInManager;
            _logger = logger;
            _context = context;
            _userManager = userManager;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public string CaptchaText { get; private set; }

        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        public string ReturnUrl { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; }

            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }

            [Required]
            public string Captcha { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            CaptchaText = GenerateCaptchaText();
            HttpContext.Session.SetString("CaptchaText", CaptchaText);

            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }

            returnUrl ??= Url.Content("~/");

            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            ReturnUrl = returnUrl;
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

        private string GenerateCaptchaText()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            var random = new Random();
            return new string(Enumerable.Repeat(chars, 5).Select(s => s[random.Next(s.Length)]).ToArray());
        }

        private bool IsCaptchaValid(string captcha)
        {
            var storedCaptchaText = HttpContext.Session.GetString("CaptchaText");
            return captcha == new string(storedCaptchaText?.Reverse().ToArray());
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            if (ModelState.IsValid)
            {
                if (!IsCaptchaValid(Input.Captcha))
                {
                    ModelState.AddModelError(string.Empty, "Invalid captcha.");
                    return Page();
                }

                var result = await _signInManager.PasswordSignInAsync(Input.Email, Input.Password, Input.RememberMe, lockoutOnFailure: false);

                if (result.Succeeded)
                {
                    await LogActivity(Input.Email, "User logged in");
                    var user = await _userManager.FindByEmailAsync(Input.Email);

                    if (user != null)
                    {
                        HttpContext.Session.SetString("UserId", user.Id);
                        HttpContext.Session.SetString("UserEmail", user.Email);

                        if (user.MustChangePassword)
                        {
                            return RedirectToPage("/Account/ChangePasswordFirstLogin");
                        }

                        return LocalRedirect(returnUrl);
                    }
                }

                if (result.RequiresTwoFactor)
                {
                    return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
                }

                if (result.IsLockedOut)
                {
                    _logger.LogWarning("User account locked out.");
                    return RedirectToPage("./Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return Page();
                }
            }

            return Page();
        }
    }
}
