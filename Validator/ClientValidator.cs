using System.Configuration;
using Trips.Models;
using TripsS.ViewModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using FluentValidation;

namespace TripsS.Validator;

public class ClientValidator : AbstractValidator<ClientViewModel>
{
   public ClientValidator()
    {
       RuleFor(x => x.FirstName).NotEmpty().WithMessage("First name is required");
       RuleFor(x => x.LastName).NotEmpty().WithMessage("Last name is required");
       RuleFor(x => x.Email).NotEmpty().WithMessage("Email is required");
       RuleFor(x => x.Email).EmailAddress().WithMessage("Email is not valid");
       RuleFor(x => x.Phone).NotEmpty().WithMessage("Phone is required");
       RuleFor(x => x.Phone).Length(9).WithMessage("Phone must have 9 digits");
   }
}
