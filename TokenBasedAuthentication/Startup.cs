using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Cors;
using Microsoft.Owin.Security.OAuth;
using Owin;

[assembly: OwinStartup(typeof(TokenBasedAuthentication.Startup))]

namespace TokenBasedAuthentication
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=316888
            app.UseCors(CorsOptions.AllowAll);

            //apply token based authentication

            //1st OAuth options
            OAuthAuthorizationServerOptions option = new OAuthAuthorizationServerOptions
            {
                // /api/token post request with username & password
                TokenEndpointPath = new PathString("/token"),
                //apply auth provider
                Provider = new ApplicationOAuthProvider(),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(60),
                AllowInsecureHttp = true

            };

            //tell the application use above option
            app.UseOAuthAuthorizationServer(option);
            //specify  bear authentication
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());
        }
    }
}
