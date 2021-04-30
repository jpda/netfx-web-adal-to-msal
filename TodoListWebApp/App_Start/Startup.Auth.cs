//----------------------------------------------------------------------------------------------
//    Copyright 2014 Microsoft Corporation
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//----------------------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

// The following using statements were added for this sample.
using Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Configuration;
using System.Globalization;

using System.Threading.Tasks;
using TodoListWebApp.Utils;
using System.Security.Claims;
using Microsoft.Owin.Security.Notifications;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Identity.Client;

namespace TodoListWebApp
{
    public partial class Startup
    {
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string appKey = ConfigurationManager.AppSettings["ida:AppKey"];
        private static string aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
        private static string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        private static string redirectUri = ConfigurationManager.AppSettings["ida:RedirectUri"];
        private static string todoListApiResource = ConfigurationManager.AppSettings["todo:TodoListResourceid"];

        public static readonly string Authority = String.Format(CultureInfo.InvariantCulture, aadInstance, tenant);

        // This is the resource ID of the AAD Graph API.  We'll need this to request a token to call the Graph API.
        static string graphResourceId = ConfigurationManager.AppSettings["ida:GraphResourceId"];

        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = clientId,
                    Authority = Authority,
                    PostLogoutRedirectUri = redirectUri,
                    RedirectUri = redirectUri,

                    Notifications = new OpenIdConnectAuthenticationNotifications()
                    {
                        //
                        // If there is a code in the OpenID Connect response, redeem it for an access token and refresh token, and store those away.
                        //
                        AuthorizationCodeReceived = OnAuthorizationCodeReceived,
                        AuthenticationFailed = OnAuthenticationFailed,
                        RedirectToIdentityProvider = ctx =>
                        {
                            var properties = ctx.OwinContext.Authentication.AuthenticationResponseChallenge.Properties;
                            if (properties.Dictionary.TryGetValue("scopeNeeded", out var scope))
                            {
                                //ctx.ProtocolMessage.Scope = scope;
                                ctx.ProtocolMessage.Resource = scope;
                            }
                            return Task.FromResult(0);
                        },
                        SecurityTokenValidated = async ctx =>
                        {
                            //var oid = ctx.AuthenticationTicket.Identity.Claims.SingleOrDefault(x => x.Type == "http://schemas.microsoft.com/identity/claims/objectidentifier").Value;
                            //var upn = ctx.AuthenticationTicket.Identity.Claims.SingleOrDefault(x => x.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn").Value;
                            //var msal = MsalBuilder.Get(oid);
                            //var homeAccount = await msal.GetAccountAsync(upn);
                            //ctx.AuthenticationTicket.Identity.AddClaim(new Claim("msalObjectId", homeAccount.HomeAccountId.Identifier));
                        }
                    }
                });
        }

        private Task OnAuthenticationFailed(AuthenticationFailedNotification
            <Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
        {
            context.HandleResponse();
            context.Response.Redirect("/Home/Error?message=" + context.Exception.Message);
            return Task.FromResult(0);
        }

        private static async Task OnAuthorizationCodeReceived(AuthorizationCodeReceivedNotification context)
        {
            var code = context.Code;
            string userObjectID = context.AuthenticationTicket.Identity.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;
            var httpContext = (context.OwinContext.Environment["System.Web.HttpContextBase"] as HttpContextBase).ApplicationInstance.Context;

            var resource = $"{graphResourceId}";

            if (context.AuthenticationTicket.Properties != null)
            {
                var properties = context.AuthenticationTicket.Properties;
                if (properties.Dictionary.TryGetValue("scopeNeeded", out var scope))
                {
                    //ctx.ProtocolMessage.Scope = scope;
                    resource = $"{scope}/.default";
                }
            }

            var msal = MsalBuilder.Get(userObjectID, httpContext);
            await msal.AcquireTokenByAuthorizationCode(new[] { $"{resource}/.default" }, code).ExecuteAsync();
            var accounts = await msal.GetAccountsAsync();
            context.AuthenticationTicket.Identity.AddClaim(new Claim("HomeAccountId", accounts.First().HomeAccountId.Identifier));
        }
    }

    public static class MsalBuilder
    {
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string appKey = ConfigurationManager.AppSettings["ida:AppKey"];
        private static string aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
        private static string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        private static string redirectUri = ConfigurationManager.AppSettings["ida:RedirectUri"];
        private static string todoListApiResource = ConfigurationManager.AppSettings["todo:TodoListResourceid"];
        public static readonly string Authority = String.Format(CultureInfo.InvariantCulture, aadInstance, tenant);

        public static IConfidentialClientApplication Get()
        {
            string userObjectID = ClaimsPrincipal.Current.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;
            return Get(userObjectID, HttpContext.Current);
        }

        public static IConfidentialClientApplication Get(string userObjectId = "", HttpContext context = null)
        {
            var msal = ConfidentialClientApplicationBuilder.Create(clientId)
                  .WithClientSecret(appKey)
                  .WithAuthority(Authority)
                  .WithRedirectUri(redirectUri)
                  .Build();

            var tokenCache = new NaiveSessionCache(userObjectId, context ?? HttpContext.Current);
            msal.UserTokenCache.SetAfterAccess(tokenCache.Persist);
            msal.UserTokenCache.SetBeforeAccess(tokenCache.Load);
            return msal;
        }
    }
}
