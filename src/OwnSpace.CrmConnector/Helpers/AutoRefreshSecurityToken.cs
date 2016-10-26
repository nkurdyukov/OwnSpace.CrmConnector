using System;
using System.ServiceModel;
using System.ServiceModel.Description;

using Microsoft.Xrm.Sdk.Client;

namespace OwnSpace.CrmConnector
{
    internal sealed class AutoRefreshSecurityToken<TProxy, TService>
        where TProxy : ServiceProxy<TService>
        where TService : class
    {
        private readonly TProxy proxy;

        private ClientCredentials deviceCredentials;

        public AutoRefreshSecurityToken(TProxy proxy)
        {
            if (proxy == null)
            {
                throw new ArgumentNullException(nameof(proxy));
            }

            this.proxy = proxy;
        }

        public void ResetCredentials()
        {
            if (proxy.ClientCredentials == null)
            {
                return;
            }

            switch (proxy.ServiceConfiguration.AuthenticationType)
            {
                case AuthenticationProviderType.ActiveDirectory:
                    proxy.ClientCredentials.UserName.UserName = null;
                    proxy.ClientCredentials.UserName.Password = null;
                    break;
                case AuthenticationProviderType.Federation:
                case AuthenticationProviderType.LiveId:
                    proxy.ClientCredentials.Windows.ClientCredential = null;
                    break;
            }
        }

        public SecurityTokenResponse AuthenticateDevice()
        {
            if (deviceCredentials == null)
            {
                deviceCredentials = DeviceIdManager.LoadOrRegisterDevice(proxy.ServiceConfiguration.CurrentIssuer.IssuerAddress.Uri);
            }

            return proxy.ServiceConfiguration.AuthenticateDevice(deviceCredentials);
        }

        public void RenewTokenIfRequired()
        {
            if (proxy.SecurityTokenResponse != null &&
                DateTime.UtcNow.AddMinutes(15) >= proxy.SecurityTokenResponse.Response.Lifetime.Expires)
            {
                try
                {
                    proxy.Authenticate();
                }
                catch (CommunicationException)
                {
                    if (proxy.SecurityTokenResponse == null ||
                        DateTime.UtcNow >= proxy.SecurityTokenResponse.Response.Lifetime.Expires)
                    {
                        throw;
                    }
                }
            }
        }
    }
}
