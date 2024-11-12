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
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;


var builder = WebApplication.CreateBuilder(args);

// Add DbContext to the service collection
builder.Services.AddDbContext<TripContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("MvcWycieczkiContext")));

builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true).AddEntityFrameworkStores<TripContext>();

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();
builder.Services.AddScoped<IClientRepository,ClientRepositorycs>();
builder.Services.AddScoped<ITripRepository,TripRepository>();
builder.Services.AddScoped<IReservationRepository, ReservationRepositorycs>();
//////////// Services
builder.Services.AddScoped<IClientService, ClientService>();
builder.Services.AddScoped<ITripService, TripService>();
builder.Services.AddScoped<IReservationService, ReservationService>();
// Validators
builder.Services.AddScoped<IValidator<ClientViewModel>, ClientValidator>();
builder.Services.AddScoped<IValidator<TripViewModel>, TripValidator>();
builder.Services.AddScoped<IValidator<ReservationViewModel>, ReservationValidator>();
//serwisy do ról

builder.Services.AddIdentityCore<IdentityUser>()
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<TripContext>();
builder.Services.AddScoped<IUserStore<IdentityUser>,UserStore<IdentityUser,IdentityRole,TripContext, 
    string, IdentityUserClaim<string>, IdentityUserRole<string>, IdentityUserLogin<string>, 
    IdentityUserToken<string>, IdentityRoleClaim<string>>>();




//Automapper
builder.Services.AddAutoMapper(options =>
{
    options.AddProfile<TripAutoMapper>();
});
//Roles
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Admin", policy => policy.RequireRole("Admin"));
    options.AddPolicy("Manager", policy => policy.RequireRole("Manager"));
    options.AddPolicy("Member", policy => policy.RequireRole("Member"));
});


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

CreateDbIfNotExists(app);
app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();


app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapRazorPages();
app.Run();

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
builder.Services.Configure<IdentityOptions>(options =>
{
    // Default Password settings.
    options.Password.RequireLowercase = true;
    options.Password.RequireDigit = true;
});


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