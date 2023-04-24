using Microsoft.AspNetCore.Identity;

namespace AspNetIdentity.Common.Entities;

public class MemberRole : IdentityUserRole<Guid>
{
    public virtual Member Member { get; set; }
    public virtual Role Role { get; set; }
}