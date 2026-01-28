using Microsoft.AspNetCore.Mvc;
using Application_Security_ASSGN2.Data;
using Application_Security_ASSGN2.Services;

namespace Application_Security_ASSGN2.Controllers
{
    public class HomeController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IEncryptionService _encryptionService;

        public HomeController(ApplicationDbContext context, IEncryptionService encryptionService)
        {
            _context = context;
            _encryptionService = encryptionService;
        }

        public async Task<IActionResult> Index()
        {
            var userId = HttpContext.Session.GetInt32("UserId");

            if (!userId.HasValue)
            {
                return RedirectToAction("Login", "Account");
            }

            var member = await _context.Members.FindAsync(userId.Value);

            if (member == null)
            {
                HttpContext.Session.Clear();
                return RedirectToAction("Login", "Account");
            }

            // Decrypt NRIC for display
            ViewBag.DecryptedNRIC = _encryptionService.Decrypt(member.NRIC);
            ViewBag.Member = member;

            return View(member);
        }

        public IActionResult Privacy()
        {
            return View();
        }
    }
}
