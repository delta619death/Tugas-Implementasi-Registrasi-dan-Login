using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SampleSecureWeb.Data;
using SampleSecureWeb.Models;
using SampleSecureWeb.ViewModels;
using BC = BCrypt.Net.BCrypt;

namespace SampleSecureWeb.Controllers
{
    public class AccountController : Controller
    {
        private readonly IUser _userData;
        private readonly ApplicationDbContext _db;

        public AccountController(IUser user, ApplicationDbContext db)
        {
            _userData = user;
            _db = db;
        }

        public ActionResult Index()
        {
            return View();
        }

        // Register action
        public ActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Register(RegistrationViewModel registrationViewModel)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    var user = new User
                    {
                        Username = registrationViewModel.Username,
                        Password = registrationViewModel.Password,
                        RoleName = "Contributor"
                    };
                    _userData.Registration(user);
                    return RedirectToAction("Index", "Home");
                }
            }
            catch (System.Exception ex)
            {
                ViewBag.Error = ex.Message;
            }
            return View(registrationViewModel);
        }

        // Login action
        public ActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Login(LoginViewModel loginViewModel)
        {
            try
            {
                loginViewModel.ReturnUrl = loginViewModel.ReturnUrl ?? Url.Content("~/");

                var user = new User
                {
                    Username = loginViewModel.Username,
                    Password = loginViewModel.Password,
                };

                var loginUser = _userData.Login(user);
                if (loginUser == null)
                {
                    ViewBag.Message = "Invalid login attempt.";
                    return View(loginViewModel);
                }

                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.Username)
                };
                var identity = new ClaimsIdentity(claims,
                    CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);

                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    principal,
                    new AuthenticationProperties
                    {
                        IsPersistent = loginViewModel.RememberLogin
                    });

                return RedirectToAction("Index", "Home");
            }
            catch (System.Exception ex)
            {
                ViewBag.Message = ex.Message;
            }

            return View(loginViewModel);
        }

        // Logout action
        public async Task<ActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home");
        }

        // Update password action
        [Authorize]
public ActionResult UpdatePassword()
{
    // Memeriksa apakah pengguna sudah login
    if (User.Identity.IsAuthenticated)
    {
        var username = User.Identity.Name; // Mendapatkan username dari identitas
        Console.WriteLine($"Logged in user: {username}");
    }
    else
    {
        Console.WriteLine("User is not logged in.");
    }

    return View();
}

        [HttpPost]
[Authorize]
public ActionResult UpdatePassword(UpdatePasswordViewModel model)
{
    try
    {
        // Logging input untuk debugging
        Console.WriteLine($"Current Password: {model.CurrentPassword}");
        Console.WriteLine($"New Password: {model.NewPassword}");
        Console.WriteLine($"Confirm New Password: {model.ConfirmNewPassword}");

        if (ModelState.IsValid)
        {
            var username = User.Identity.Name;

            if (string.IsNullOrEmpty(username))
            {
                throw new Exception("User is not logged in.");
            }

            // Mencari user berdasarkan username
            var user = _db.Users.FirstOrDefault(u => u.Username == username);

            if (user == null)
            {
                throw new Exception("User not found.");
            }

            // Verifikasi current password
            if (!BC.Verify(model.CurrentPassword, user.Password))
            {
                throw new Exception("Current password is incorrect.");
            }

            // Cek apakah NewPassword atau ConfirmNewPassword bernilai null
            if (string.IsNullOrEmpty(model.NewPassword) || string.IsNullOrEmpty(model.ConfirmNewPassword))
            {
                throw new Exception("New password or confirm password cannot be null.");
            }

            // Hash password baru dan update di database
            user.Password = BC.HashPassword(model.NewPassword);
            _db.Users.Update(user);
            _db.SaveChanges();

            ViewBag.Message = "Password updated successfully!";
            return RedirectToAction("Index", "Home");
        }
        else
        {
            ViewBag.Error = "Invalid input. Please check your entries.";
        }
    }
    catch (Exception ex)
    {
        ViewBag.Error = ex.Message;
    }

    return View(model);
}
    }
}
