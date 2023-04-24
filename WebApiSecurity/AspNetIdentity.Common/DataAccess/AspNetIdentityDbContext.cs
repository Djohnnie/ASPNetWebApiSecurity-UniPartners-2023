using AspNetIdentity.Common.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AspNetIdentity.Common.DataAccess;

public class AspNetIdentityDbContext : IdentityDbContext<Member, Role, Guid, MemberClaim, MemberRole, MemberLogin, RoleClaim, MemberToken>
{
    public AspNetIdentityDbContext(DbContextOptions<AspNetIdentityDbContext> options) : base(options) { }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.ApplyConfigurationsFromAssembly(typeof(AspNetIdentityDbContext).Assembly);

        modelBuilder.Entity<MemberRole>(x =>
        {
            x.HasKey(ur => new { ur.UserId, ur.RoleId });

            x.HasOne(ur => ur.Role)
                .WithMany(r => r.MemberRoles)
                .HasForeignKey(ur => ur.RoleId)
                .IsRequired();

            x.HasOne(ur => ur.Member)
                .WithMany(r => r.MemberRoles)
                .HasForeignKey(ur => ur.UserId)
                .IsRequired();
        });
    }
}