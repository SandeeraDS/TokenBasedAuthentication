using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Web;

namespace TokenBasedAuthentication.Models
{
    public class ApplicationUser  : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }

    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext() : base("DefaultConnection") { }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<ApplicationUser>()
                .ToTable("User");
            modelBuilder.Entity<IdentityRole>()
               .ToTable("Role");
            modelBuilder.Entity<IdentityUserRole>()
               .ToTable("UserRole");
            modelBuilder.Entity<IdentityUserClaim>()
               .ToTable("UserClaim");
            modelBuilder.Entity<IdentityUserLogin>()
               .ToTable("UserLogin");
        }

    }


}