using Microsoft.AspNetCore.Identity;

namespace AspNetIdentity.Common.Entities;

public class Role : IdentityRole<Guid>
{
    public virtual IList<MemberRole> MemberRoles { get; set; }
}