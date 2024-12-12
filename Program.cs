using Microsoft.EntityFrameworkCore;
using Trips;
using Trips.Data;
using TripsS.Repositories;
using TripsS.Repositories.Interfaces;
using TripsS.Services;
using TripsS.Services.Interfaces;
using TripsS.ViewModel;
using TripsS.Validator;
using FluentValidation;
using TripsS.AutoMapper;
using Microsoft.AspNetCore.Identity;
using TripsS.Models;
using System.Diagnostics;



var builder = WebApplication.CreateBuilder(args);

// Add DbContext to the service collection
builder.Services.AddDbContext<TripContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("MvcWycieczkiContext")));

// Add Identity with custom ApplicationUser and Role support
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.SignIn.RequireConfirmedAccount = false;
    options.SignIn.RequireConfirmedEmail = false;
    // Configure password settings
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = false; // Change if required
    options.Password.RequiredLength = 6;       // Adjust length as necessary
    options.Password.RequireNonAlphanumeric = false; // Adjust if required
})
    .AddEntityFrameworkStores<TripContext>()
    .AddDefaultTokenProviders()
.AddDefaultUI();

// Add session services to the service container
builder.Services.AddDistributedMemoryCache(); // To store session data in memory
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30); // Czas trwania sesji
    options.Cookie.HttpOnly = true;// Cookies mog¹ byæ dostêpne tylko przez HTTP (nie w JS)
    
    options.Cookie.IsEssential = true; // Wa¿ne dla polityki cookies (przyjêcie zgody)
});

// Add additional services
builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();

// Repositories
builder.Services.AddScoped<IClientRepository, ClientRepositorycs>();
builder.Services.AddScoped<ITripRepository, TripRepository>();
builder.Services.AddScoped<IReservationRepository, ReservationRepositorycs>();

// Services
builder.Services.AddScoped<IClientService, ClientService>();
builder.Services.AddScoped<ITripService, TripService>();
builder.Services.AddScoped<IReservationService, ReservationService>();

// Validators
builder.Services.AddScoped<IValidator<ClientViewModel>, ClientValidator>();
builder.Services.AddScoped<IValidator<TripViewModel>, TripValidator>();
builder.Services.AddScoped<IValidator<ReservationViewModel>, ReservationValidator>();

// Automapper configuration
builder.Services.AddAutoMapper(options =>
{
    options.AddProfile<TripAutoMapper>();
});

// Authorization roles
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Admin", policy => policy.RequireRole("Admin"));
    options.AddPolicy("Manager", policy => policy.RequireRole("Manager"));
    options.AddPolicy("Member", policy => policy.RequireRole("Member"));
});

var app = builder.Build();

// Configure the HTTP request pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

CreateDbIfNotExists(app);
//Dodaje sesji
// Ograniczenie u¿ytkowania programu
OpenBrowser("https://www.google.com");
app.UseSession();
app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

await InitializeRolesAsync(app); // Ensure roles are created
app.Run();

// Create database if it does not exist
static void CreateDbIfNotExists(IHost host)
{
    using (var scope = host.Services.CreateScope())
    {
        var services = scope.ServiceProvider;
        try
        {
            var context = services.GetRequiredService<TripContext>();
            DbInitializer.Init(context);
        }
        catch (Exception ex)
        {
            var logger = services.GetRequiredService<ILogger<Program>>();
            logger.LogError(ex, "An error occurred creating the DB.");
        }
    }
}

// Initialize roles if not already created
static async Task InitializeRolesAsync(IHost app)
{
    using (var scope = app.Services.CreateScope())
    {
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        var roles = new[] { "Admin", "Manager", "Member" };

        foreach (var role in roles)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                await roleManager.CreateAsync(new IdentityRole(role));
            }
        }
    }
}

static void OpenBrowser(string url)
{
    try
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = url,
            UseShellExecute = true
        });
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Could not open browser: {ex.Message}");
    }
}




