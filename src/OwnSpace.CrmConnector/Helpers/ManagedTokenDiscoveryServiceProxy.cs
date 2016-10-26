using System;
using System.ServiceModel.Description;

using Microsoft.Xrm.Sdk.Client;
using Microsoft.Xrm.Sdk.Discovery;

namespace OwnSpace.CrmConnector.Helpers
{
    internal sealed class ManagedTokenDiscoveryServiceProxy : DiscoveryServiceProxy
    {
        private readonly AutoRefreshSecurityToken<DiscoveryServiceProxy, IDiscoveryService> proxyManager;

        public ManagedTokenDiscoveryServiceProxy(Uri serviceUri, ClientCredentials userCredentials)
            : base(serviceUri, null, userCredentials, null)
        {
            proxyManager = new AutoRefreshSecurityToken<DiscoveryServiceProxy, IDiscoveryService>(this);
        }

        public ManagedTokenDiscoveryServiceProxy(IServiceManagement<IDiscoveryService> serviceManagement, SecurityTokenResponse securityTokenRes)
            : base(serviceManagement, securityTokenRes)
        {
            proxyManager = new AutoRefreshSecurityToken<DiscoveryServiceProxy, IDiscoveryService>(this);
        }

        public ManagedTokenDiscoveryServiceProxy(IServiceManagement<IDiscoveryService> serviceManagement, ClientCredentials userCredentials)
            : base(serviceManagement, userCredentials)
        {
            proxyManager = new AutoRefreshSecurityToken<DiscoveryServiceProxy, IDiscoveryService>(this);
        }

        protected override SecurityTokenResponse AuthenticateDeviceCore()
        {
            return proxyManager.AuthenticateDevice();
        }

        protected override void AuthenticateCore()
        {
            proxyManager.ResetCredentials();
            base.AuthenticateCore();
        }

        protected override void ValidateAuthentication()
        {
            proxyManager.RenewTokenIfRequired();
            base.ValidateAuthentication();
        }
    }
}
