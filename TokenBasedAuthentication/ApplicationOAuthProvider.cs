using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using TokenBasedAuthentication.Models;

namespace TokenBasedAuthentication
{
    public class ApplicationOAuthProvider : OAuthAuthorizationServerProvider
    {
        //To Authenticate Client Device based given client id and secret code
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {

            context.Validated();
        }

        //authenticate based on username and password
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {

            //have to check user name password from the databse
            var userStore = new UserStore<ApplicationUser>(new ApplicationDbContext());
            var manager = new UserManager<ApplicationUser>(userStore);

            var user = await manager.FindAsync(context.UserName,context.Password);

            if(user != null)
            {
                //claims related to the logged in user
                //claims = statement about the logged in user
                var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                //now can add claims to this identity object

                identity.AddClaim(new Claim("Username", user.UserName));
                identity.AddClaim(new Claim("Email",user.Email));
                identity.AddClaim(new Claim("FirstName",user.FirstName));
                identity.AddClaim(new Claim("LastName",user.LastName));
                identity.AddClaim(new Claim("LoggedOn",DateTime.Now.ToString()));
                context.Validated(identity);

            }
            else
            {
                return;
            }
        }



    }
}