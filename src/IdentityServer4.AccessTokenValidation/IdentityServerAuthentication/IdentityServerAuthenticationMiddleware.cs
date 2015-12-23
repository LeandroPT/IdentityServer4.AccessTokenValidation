using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer4.AccessTokenValidation
{
    public class IdentityServerAuthenticationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IdentityServerAuthenticationOptions _options;

        private readonly RequestDelegate _localValidation;
        private readonly RequestDelegate _remoteValidation;

        public IdentityServerAuthenticationMiddleware(RequestDelegate next, IApplicationBuilder app, IdentityServerAuthenticationOptions options)
        {
            _next = next;
            _options = options;

            if (options.ValidationMode == ValidationMode.Both || 
                options.ValidationMode == ValidationMode.Local)
            {
                var local = app.New();
                _localValidation = local.Build();
            }
            if (options.ValidationMode == ValidationMode.Both || 
                options.ValidationMode == ValidationMode.Remote)
            {
                var remote = app.New();
                //remote.UseIntrospectionAuthentication(null);
                _remoteValidation = remote.Build();
            }
        }

        public async Task Invoke(HttpContext context)
        {
            var token = "";

            // seems to be a JWT
            if (token.Contains('.'))
            {
                // see if local validation is setup
                if (_localValidation != null)
                {
                    await _localValidation(context);
                    return;
                }

                // otherwise use validation endpoint
                if (_remoteValidation != null)
                {
                    await _remoteValidation(context);
                    return;
                }
            }
            else
            {
                // use validation endpoint
                if (_remoteValidation != null)
                {
                    await _remoteValidation(context);
                    return;
                }

                //_logger.WriteWarning("No validator configured for reference token");
            }

            await _next(context);
        }
    }
}
