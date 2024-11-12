using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Trips.Models;
using TripsS.Models;

namespace Trips;

public class TripContext : IdentityDbContext<IdentityUser>
{
    public DbSet<Trip> Trips { get; set; }
    public DbSet<Client> Clients { get; set; }
    public DbSet<Reservation> Reservations { get; set; }
    public DbSet<UserActivity> UserActivities { get; set; }

    public TripContext(DbContextOptions<TripContext> options) : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.Entity<Trip>().ToTable("Trips");
        modelBuilder.Entity<Client>().ToTable("Clients");
        modelBuilder.Entity<Reservation>().ToTable("Reservations");
    }
}
