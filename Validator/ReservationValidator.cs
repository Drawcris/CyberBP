namespace TripsS.Validator;
using FluentValidation;
using TripsS.ViewModel;
public class ReservationValidator : AbstractValidator<ReservationViewModel>
{
    public ReservationValidator()
    {
        RuleFor(x => x.IdClient).NotEmpty().WithMessage("IdClient is required");
        RuleFor(x => x.IdTrip).NotEmpty().WithMessage("IdTrip is required");
        RuleFor(x => x.ReservationDate).NotEmpty().WithMessage("ReservationDate is required");
        RuleFor(x => x.ReservationDate).GreaterThan(DateTime.Now).WithMessage("ReservationDate must be greater than current date");
    }
}
