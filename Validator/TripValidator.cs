using FluentValidation;
using TripsS.ViewModel;
namespace TripsS.Validator
{
    public class TripValidator : AbstractValidator<TripViewModel>
    {
        public TripValidator()
        {
           
            
            RuleFor(x => x.StartTrip.GetDateTimeFormats()).NotEmpty().WithMessage("StartTrip is required");
            RuleFor(x => x.EndTrip.GetDateTimeFormats()).NotEmpty().WithMessage("EndTrip is required");
            RuleFor(x => x.EndTrip).GreaterThan(x => x.StartTrip).WithMessage("EndDate must be greater than StartDate");
            RuleFor(x => x.Price).NotEmpty().WithMessage("Price is required");
            RuleFor(x => x.Price).GreaterThan(0).WithMessage("Price must be greater than 0");
        }
    }
}
