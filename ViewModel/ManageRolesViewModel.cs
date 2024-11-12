using System.Collections.Generic;
using Microsoft.AspNetCore.Identity;

namespace TripsS.ViewModel;
public class ManageRolesViewModel
{
    public string UserId { get; set; }
    public IList<string> UserRoles { get; set; }
    public List<IdentityRole> AllRoles { get; set; }
    
}
