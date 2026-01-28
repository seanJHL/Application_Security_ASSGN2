using Microsoft.EntityFrameworkCore;
using Application_Security_ASSGN2.Models;

namespace Application_Security_ASSGN2.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<Member> Members { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }
        public DbSet<PasswordHistory> PasswordHistories { get; set; }
        public DbSet<PasswordResetToken> PasswordResetTokens { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configure Member entity
            modelBuilder.Entity<Member>(entity =>
            {
                entity.HasKey(e => e.Id);
                
                // Unique index on Email
                entity.HasIndex(e => e.Email).IsUnique();
                
                entity.Property(e => e.FirstName).IsRequired().HasMaxLength(50);
                entity.Property(e => e.LastName).IsRequired().HasMaxLength(50);
                entity.Property(e => e.Gender).IsRequired().HasMaxLength(10);
                entity.Property(e => e.NRIC).IsRequired().HasMaxLength(255); // Encrypted will be longer
                entity.Property(e => e.Email).IsRequired().HasMaxLength(100);
                entity.Property(e => e.PasswordHash).IsRequired();
                entity.Property(e => e.ResumePath).HasMaxLength(255);
                entity.Property(e => e.WhoAmI).HasMaxLength(500);
                entity.Property(e => e.SessionToken).HasMaxLength(100);
                entity.Property(e => e.TwoFactorCode).HasMaxLength(10);
            });

            // Configure AuditLog entity
            modelBuilder.Entity<AuditLog>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Action).IsRequired().HasMaxLength(50);
                entity.Property(e => e.IpAddress).HasMaxLength(45);
                entity.Property(e => e.Details).HasMaxLength(500);

                // Relationship with Member (optional - for failed login attempts without user)
                entity.HasOne(e => e.User)
                    .WithMany(m => m.AuditLogs)
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.SetNull);
            });

            // Configure PasswordHistory entity
            modelBuilder.Entity<PasswordHistory>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.PasswordHash).IsRequired();

                entity.HasOne(e => e.Member)
                    .WithMany(m => m.PasswordHistories)
                    .HasForeignKey(e => e.MemberId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            // Configure PasswordResetToken entity
            modelBuilder.Entity<PasswordResetToken>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Token).IsRequired().HasMaxLength(100);
                
                // Index on Token for faster lookup
                entity.HasIndex(e => e.Token);

                entity.HasOne(e => e.Member)
                    .WithMany(m => m.PasswordResetTokens)
                    .HasForeignKey(e => e.MemberId)
                    .OnDelete(DeleteBehavior.Cascade);
            });
        }
    }
}
