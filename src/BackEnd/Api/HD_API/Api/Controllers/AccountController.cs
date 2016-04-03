namespace Api.Controllers
{

	#region Using
	using Microsoft.AspNet.Authorization;
	using Microsoft.AspNet.Identity;
	using Microsoft.AspNet.Mvc;
	using System.Linq;
	using System.Threading.Tasks;
	using Api.Models;
	using Api.ViewModels.Account;
	#endregion

	[Route("api/account")]
	public class AccountController : Controller
	{
		private readonly SignInManager<ApplicationUser> _signInManager;
		private readonly UserManager<ApplicationUser> _userManager;

		public AccountController(
			SignInManager<ApplicationUser> signInManager,
			UserManager<ApplicationUser> userManager)
		{
			_signInManager = signInManager;
			_userManager = userManager;
		}

		//
		// POST: /Account/Login
		[HttpPost("login")]
		[AllowAnonymous]
		public bool Login([FromBody]LoginViewModel model, string returnUrl = null)
		{
			bool isLogin = false;
			// This doesn't count login failures towards account lockout
			// To enable password failures to trigger account lockout, set lockoutOnFailure: true
			ApplicationUser find = _userManager.Users.FirstOrDefault(x => x.Email == model.Email);
			if (find != null)
			{
				var result = _signInManager.PasswordSignInAsync(find, model.Password, true, lockoutOnFailure: false);
				result.Wait();
				if (result.Result.Succeeded)
				{
					isLogin = true;
				}
			}

			return isLogin;

		}

		//
		// POST: /Account/LogOff
		[HttpPost("logoff")]
		[Authorize]
		public async Task<IActionResult> LogOff()
		{
			await _signInManager.SignOutAsync();
			return Ok();
		}

		[HttpGet("isAuthorized")]
		public bool IsAuthorized()
		{
			try
			{
				return this.User.Identities != null
					&& this.User.Identities.Count() > 0
					&& this.User.Identity != null
					&& this.User.Identity.IsAuthenticated
					&& !string.IsNullOrWhiteSpace(this.User.Identity.Name);
			}
			catch
			{
				return false;
			}
		}

	}
}
