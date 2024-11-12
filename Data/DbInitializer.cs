using Microsoft.AspNetCore.Identity;
using Trips.Models;
using TripsS.Models;
namespace Trips.Data
{
    public class DbInitializer
    {
        public static void Init(TripContext context)
        {
            context.Database.EnsureCreated();

            if (!context.UserActivities.Any())
            {
                var activities = new UserActivity[]
                {
               new UserActivity { UserName = "Admin", ActionDate = DateTime.Now, ActionDescription = "System initialized" }
                };
                foreach (var activity in activities)
                {
                    context.UserActivities.Add(activity);
                }
                context.SaveChanges();
            }

            if (context.Trips.Any())
            {
                return;
            }
            var trips = new Trip[]
            {
                new Trip { From = "Warszawa", To = "Kraków", StartTrip = new DateTime(2021, 12, 12), EndTrip = new DateTime(2021, 12, 13), Price = 100},
                new Trip { From = "Kraków", To = "Warszawa", StartTrip = new DateTime(2021, 12, 14), EndTrip = new DateTime(2021, 12, 15), Price = 100},
                new Trip { From = "Warszawa", To = "Gdańsk", StartTrip = new DateTime(2021, 12, 16), EndTrip = new DateTime(2021, 12, 17), Price = 100},
                new Trip { From = "Gdańsk", To = "Warszawa", StartTrip = new DateTime(2021, 12, 18), EndTrip = new DateTime(2021, 12, 19), Price = 100}

            };
            foreach (Trip t in trips)
            {
                context.Trips.Add(t);
            }
            context.SaveChanges();

            var clients = new Client[]
            {
                    new Client { FirstName = "Jan", LastName = "Kowalski", Pesel = 123456789, Email = "askdlaskd@gmail.com"},
                    new Client { FirstName = "Anna", LastName = "Nowak", Pesel = 987654321, Email = "aSDASDAS@gmail.com"},
                    new Client { FirstName = "Piotr", LastName = "Kowalczyk", Pesel = 123123123, Email = "kakaka@gmail.com"}
            };
            foreach (Client c in clients)
            {
                context.Clients.Add(c);
            }
            context.SaveChanges();
            var Roles = new IdentityRole[]
            {
                new IdentityRole { Name = "Admin", NormalizedName = "ADMIN", Id = "1" },
                new IdentityRole { Name = "Manager", NormalizedName = "MANAGER", Id = "2"},
                new IdentityRole { Name = "Member", NormalizedName = "MEMBER", Id = "3"}
            };
            foreach (IdentityRole r in Roles)
            {
                context.Roles.Add(r);
            }
            context.SaveChanges();

            
         
        }
    }
}
