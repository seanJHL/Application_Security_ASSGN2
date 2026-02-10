using Microsoft.EntityFrameworkCore;
using Application_Security_ASSGN2.Data;
using Application_Security_ASSGN2.Services;
using Application_Security_ASSGN2.Middleware;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// Configure Entity Framework with SQLite
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

// Configure Session with security best practices
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(
        builder.Configuration.GetValue<int>("SessionSettings:TimeoutInMinutes", 30));
    options.Cookie.HttpOnly = true;        // Prevent JavaScript access to session cookie
    options.Cookie.IsEssential = true;
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment() 
        ? CookieSecurePolicy.SameAsRequest 
        : CookieSecurePolicy.Always;       // Require HTTPS in production
    options.Cookie.SameSite = SameSiteMode.Strict;  // Prevent CSRF attacks
    options.Cookie.Name = ".AppSecurity.Session";
});

// Configure HttpClient for reCAPTCHA service
builder.Services.AddHttpClient();

// Register application services
builder.Services.AddScoped<IPasswordService, PasswordService>();
builder.Services.AddScoped<IEncryptionService, EncryptionService>();
builder.Services.AddScoped<IReCaptchaService, ReCaptchaService>();
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<IAuditLogService, AuditLogService>();
builder.Services.AddScoped<IInputSanitizationService, InputSanitizationService>();

// Configure anti-forgery with security best practices
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment() 
        ? CookieSecurePolicy.SameAsRequest 
        : CookieSecurePolicy.Always;
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

// Configure cookie policy
builder.Services.Configure<CookiePolicyOptions>(options =>
{
    options.CheckConsentNeeded = context => false;
    options.MinimumSameSitePolicy = SameSiteMode.Strict;
    options.HttpOnly = Microsoft.AspNetCore.CookiePolicy.HttpOnlyPolicy.Always;
    options.Secure = builder.Environment.IsDevelopment() 
        ? CookieSecurePolicy.SameAsRequest 
        : CookieSecurePolicy.Always;
});

var app = builder.Build();

// ============================================
// SECURITY MIDDLEWARE PIPELINE
// Order matters! Configure in the correct sequence
// ============================================

// 1. Global Exception Handler - Catches all unhandled exceptions
// Prevents stack traces and internal details from being exposed
app.UseGlobalExceptionHandler();

// 2. Security Headers - Adds XSS, CSP, and other security headers
// Protects against XSS, clickjacking, MIME sniffing attacks
app.UseSecurityHeaders();

// 3. HTTPS Redirection and HSTS
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}
app.UseHttpsRedirection();

// 4. Handle HTTP status codes with custom error pages
// Prevents default server error pages that may expose server info
app.UseStatusCodePagesWithReExecute("/Error/{0}");

// 5. Static files with security options
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = ctx =>
    {
        // Add security headers for static files
        ctx.Context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
        
        // Cache static files for 1 year (they have version hashes)
        if (ctx.Context.Request.Path.StartsWithSegments("/lib") ||
            ctx.Context.Request.Path.StartsWithSegments("/css") ||
            ctx.Context.Request.Path.StartsWithSegments("/js"))
        {
            ctx.Context.Response.Headers.Append("Cache-Control", "public, max-age=31536000");
        }
    }
});

// 6. Cookie policy
app.UseCookiePolicy();

// 7. Routing
app.UseRouting();

// 8. Session - Must be before authentication/authorization
app.UseSession();

// 9. Custom session validation middleware
app.UseSessionValidation();

// 10. Authorization
app.UseAuthorization();

// Configure default route for MVC
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// Ensure database is created and migrations applied
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var context = services.GetRequiredService<ApplicationDbContext>();
        context.Database.EnsureCreated();
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogInformation("Database initialized successfully.");
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred while creating/migrating the database.");
    }
}

// Display application URLs when server starts
app.Lifetime.ApplicationStarted.Register(() =>
{
    Console.WriteLine();

    Console.WriteLine();
    Console.WriteLine("🌐 Application is now running at:");
    
    var addresses = app.Urls;
    if (addresses.Any())
    {
        foreach (var address in addresses)
        {
            Console.WriteLine($"   → {address}");
        }
    }
    else
    {
        Console.WriteLine("   → http://localhost:5157");
        Console.WriteLine("   → https://localhost:7164");
    }
    
    Console.WriteLine();
    Console.WriteLine("📝 Press Ctrl+C to stop the server");
    Console.WriteLine();
});

app.Run();
