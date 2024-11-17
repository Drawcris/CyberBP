using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using TripsS.ViewModel;
using Microsoft.EntityFrameworkCore;
using Trips;
using TripsS.Models;

[Authorize(Roles = "Admin")]
public class AdminController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly TripContext _context;


    public AdminController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, TripContext context)
    {
        _userManager = userManager;
        _context = context;
        _roleManager = roleManager;
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

    // Akcja dla UserActivities
    public async Task<IActionResult> UserActivities()
    {
        var activities = await _context.UserActivities.ToListAsync();
        return View(activities);
    }

    // GET: Admin/Index
    public IActionResult Index()
    {
        var users = _userManager.Users.ToList();
        return View(users);
    }

    // GET: Admin/CreateUser
    public IActionResult CreateUser()
    {
        return View();
    }

    // POST: Admin/CreateUser
    [HttpPost]
    public async Task<IActionResult> CreateUser(CreateUserViewModel model)
    {
        if (ModelState.IsValid)
        {
            var user = new ApplicationUser { UserName = model.Email, Email = model.Email, EmailConfirmed = true, MustChangePassword = true };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                await LogActivity(user.UserName, "User account created by Admin");
                return RedirectToAction("Index");
            }
            if (!result.Succeeded)
            {
                   await LogActivity(user.UserName, "Failed to creating User by Admin");
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);

            }
        }
        return View(model);
    }

    // POST: Admin/DeleteUser
    [HttpPost]
    public async Task<IActionResult> DeleteUser(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound();
        }

        var result = await _userManager.DeleteAsync(user);
        await LogActivity(user.UserName, "User account deleted");

        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);

            }
        }

        return RedirectToAction("Index");
    }


public async Task<IActionResult> Edit(string userId)
    {
        if (userId == null)
        {
            return NotFound();
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound();
        }

        var model = new EditUserViewModel
        {
            UserId = user.Id,
            Email = user.Email,
            UserName = user.UserName
        };

        return View(model);
    }

    // POST: Admin/Edit
    [HttpPost]
    public async Task<IActionResult> Edit(EditUserViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userManager.FindByIdAsync(model.UserId);
        if (user == null)
        {
            return NotFound();
        }

        user.Email = model.Email;
        user.UserName = model.UserName;

        var updateResult = await _userManager.UpdateAsync(user);
        if (!updateResult.Succeeded)
        {

            foreach (var error in updateResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);
        }

        if (!string.IsNullOrEmpty(model.NewPassword))
        {
            var passwordChangeResult = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
            if (!passwordChangeResult.Succeeded)
            {
                await LogActivity(user.UserName, "Failed to edit User by Admin");

                foreach (var error in passwordChangeResult.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return View(model);
            }
        }
        await LogActivity(user.UserName, "User data has been changed by Admin");

        return RedirectToAction("Index");
    }

    // POST: Admin/BlockUser
    [HttpPost]
    public async Task<IActionResult> BlockUser(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound();
        }

        user.LockoutEnd = DateTimeOffset.MaxValue;
        var result = await _userManager.UpdateAsync(user);

        if (result.Succeeded)
        {
            await LogActivity(user.UserName, "User account blocked");
            return RedirectToAction("Index");
        }

        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }

        return View("Error");
    }

    // POST: Admin/UnlockUser
    [HttpPost]
    public async Task<IActionResult> UnlockUser(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound();
        }

        user.LockoutEnd = DateTime.Now;
        var result = await _userManager.UpdateAsync(user);

        if (result.Succeeded)
        {
            await LogActivity(user.UserName, "User account unlocked");
            return RedirectToAction("Index");
        }

        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }

        return View("Error");
    }



    // GET: Admin/ManageRoles/userId
    public async Task<IActionResult> ManageRoles(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound();
        }

        var userRoles = await _userManager.GetRolesAsync(user);
        var roles = _roleManager.Roles.ToList();

        var model = new ManageRolesViewModel
        {
            UserId = user.Id,
            UserRoles = userRoles,
            AllRoles = roles
        };

        return View(model);
    }

    // POST: Admin/UpdateRoles
    [HttpPost]
    public async Task<IActionResult> UpdateRoles(string userId, List<string> roles)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound();
        }

        var userRoles = await _userManager.GetRolesAsync(user);
        var rolesToAdd = roles.Except(userRoles).ToList();
        var rolesToRemove = userRoles.Except(roles).ToList();

        if (rolesToAdd.Any())
        {
            await _userManager.AddToRolesAsync(user, rolesToAdd);
            await LogActivity(user.UserName, "User add role");

        }

        if (rolesToRemove.Any())
        {
            await _userManager.RemoveFromRolesAsync(user, rolesToRemove);
            await LogActivity(user.UserName, "User removed role");

        }

        return RedirectToAction("Index");
    }

    // GET: Account/ChangePassword
    public IActionResult ChangePassword()
    {
        return View();
    }

    // POST: Account/ChangePassword
    //[HttpPost]
    //public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
    //{
    //    if (!ModelState.IsValid)
    //    {
    //        return View(model);
    //    }

    //    var user = await _userManager.GetUserAsync(User);
    //    if (user == null)
    //    {
    //        return RedirectToAction("Login");
    //    }

    //    var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
    //    if (result.Succeeded)
    //    {
    //        user.PasswordExpirationDate = DateTime.UtcNow.AddDays(90);
    //        user.LastPasswordChangeDate = DateTime.UtcNow;
    //        await _userManager.UpdateAsync(user);
    //        return RedirectToAction("Index", "Home");
    //    }

    //    foreach (var error in result.Errors)
    //    {
    //        ModelState.AddModelError(string.Empty, error.Description);
    //    }

    //    return View(model);
    //}

    //// GET: Account/ResetPassword
    //public IActionResult ResetPassword(string code = null)
    //{
    //    return code == null ? View("Error") : View(new ResetPasswordViewModel { Code = code });
    //}

    //// POST: Account/ResetPassword
    //[HttpPost]
    //public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
    //{
    //    if (!ModelState.IsValid)
    //    {
    //        return View(model);
    //    }

    //    var user = await _userManager.FindByEmailAsync(model.Email);
    //    if (user == null)
    //    {
    //        return RedirectToAction("ResetPasswordConfirmation");
    //    }

    //    var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
    //    if (result.Succeeded)
    //    {
    //        user.PasswordExpirationDate = DateTime.UtcNow.AddDays(90);
    //        user.LastPasswordChangeDate = DateTime.UtcNow;
    //        await _userManager.UpdateAsync(user);
    //        return RedirectToAction("ResetPasswordConfirmation");
    //    }

    //    foreach (var error in result.Errors)
    //    {
    //        ModelState.AddModelError(string.Empty, error.Description);
    //    }

    //    return View(model);
    //}

    // GET: Account/ResetPasswordConfirmation
    public IActionResult ResetPasswordConfirmation()
    {
        return View();
    }
}
