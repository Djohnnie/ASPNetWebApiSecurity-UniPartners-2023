using Microsoft.AspNetCore.Identity;

namespace AspNetIdentity.Common.Entities;

public class Member : IdentityUser<Guid>
{
    public string RefreshToken { get; set; }
    public DateTime? RefreshTokenExpiry { get; set; }

    public virtual IList<MemberRole> MemberRoles { get; set; }
}