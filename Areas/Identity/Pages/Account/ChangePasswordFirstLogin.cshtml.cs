using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TripsS.Models;

namespace TripsS.Areas.Identity.Pages.Account;
public class ChangePasswordFirstLoginModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    public string UserEmail { get; private set; }
    public int A { get; private set; }
    public int X { get; private set; }

    public ChangePasswordFirstLoginModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }

    public IActionResult OnGet()
    {
        // Retrieve session values for UserId and Email
        
        var userId = HttpContext.Session.GetString("UserId");  // Use the same key used for setting session
        var email = HttpContext.Session.GetString("UserEmail");  // Use the same key used for setting session

        // If either value is missing, redirect to login page
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(email))
        {
            return RedirectToPage("./Login");
        }

        // Generate random values (X and A) for the password change logic
        var random = new Random();
        X = random.Next(1, 11);  // Generate a random number between 1 and 10
        A = email.Length;  // Use the email length as part of your logic

        UserEmail = email;  // Set the email to be displayed on the page

        // Store the generated values in session
        HttpContext.Session.SetInt32("XValue", X);
        HttpContext.Session.SetInt32("AValue", A);

        // Return the page for further processing
        return Page();
    }


    public async Task<IActionResult> OnPostAsync(string functionResult, string newPassword, string confirmPassword)
    {
        var userId = HttpContext.Session.GetString("UserId");
        if (userId == null) return RedirectToPage("./Login");

        var a = HttpContext.Session.GetInt32("AValue") ?? 0;
        var x = HttpContext.Session.GetInt32("XValue") ?? 0;

        double expectedResult = a * Math.Log(2 + x);
       

        if (Math.Abs(expectedResult - double.Parse(functionResult)) > 1)
        {
            ModelState.AddModelError("", "Incorrect function result.");
            return Page();
        }

        if (newPassword != confirmPassword)
        {
            ModelState.AddModelError("", "Passwords do not match.");
            return Page();
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user != null)
        {
            user.PasswordHash = _userManager.PasswordHasher.HashPassword(user, newPassword);
            user.MustChangePassword = false;
            await _userManager.UpdateAsync(user);

            await _signInManager.SignInAsync(user, isPersistent: false);
            return RedirectToPage("./Login");
        }

        return RedirectToPage("./Login");
    }
}

